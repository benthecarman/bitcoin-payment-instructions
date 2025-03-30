//! A [`HrnResolver`] which uses `reqwest` and `dns.google` (8.8.8.8) to resolve Human Readable
//! Names into bitcoin payment instructions.

use std::boxed::Box;
use std::fmt::Write;
use std::str::FromStr;

use serde::Deserialize;

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash as _;

use dnssec_prover::query::{ProofBuilder, QueryBuf};
use dnssec_prover::rr::{Name, TXT_TYPE};

use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescriptionRef};

use crate::amount::Amount;
use crate::dnssec_utils::resolve_proof;
use crate::hrn::HumanReadableName;
use crate::hrn_resolution::{
	HrnResolution, HrnResolutionFuture, HrnResolver, LNURLResolutionFuture,
};

const DOH_ENDPOINT: &'static str = "https://dns.google/dns-query?dns=";

/// An [`HrnResolver`] which uses `reqwest` and `dns.google` (8.8.8.8) to resolve Human Readable
/// Names into bitcoin payment instructions.
///
/// Note that using this may reveal our IP address to the recipient and information about who we're
/// paying to Google (via `dns.google`).
pub struct HTTPHrnResolver;

fn query_to_url(query: QueryBuf) -> String {
	let base64_len = base64::encoded_len(query.len(), true)
		.expect("Queries should fit in a usize-len base64 string");
	let mut query_string = String::with_capacity(base64_len + DOH_ENDPOINT.len());

	query_string += DOH_ENDPOINT;
	use base64::Engine;
	base64::engine::general_purpose::STANDARD_NO_PAD.encode_string(&query[..], &mut query_string);

	query_string
}

#[derive(Deserialize)]
struct LNURLInitResponse {
	callback: String,
	#[serde(rename = "maxSendable")]
	max_sendable: u64,
	#[serde(rename = "minSendable")]
	min_sendable: u64,
	metadata: String,
	tag: String,
}

#[derive(Deserialize)]
struct LNURLMetadata(Vec<(String, String)>);

#[derive(Deserialize)]
struct LNURLCallbackResponse {
	pr: String,
	routes: Vec<String>,
}

const DNS_ERR: &'static str = "DNS Request to dns.google failed";

impl HTTPHrnResolver {
	async fn resolve_dns(&self, hrn: &HumanReadableName) -> Result<HrnResolution, &'static str> {
		let dns_name =
			Name::try_from(format!("{}.user._bitcoin-payment.{}.", hrn.user(), hrn.domain()))
				.map_err(|_| "The provided HRN was too long to fit in a DNS name")?;
		let (mut proof_builder, initial_query) = ProofBuilder::new(&dns_name, TXT_TYPE);
		let mut pending_queries = vec![initial_query];

		while let Some(query) = pending_queries.pop() {
			let client = reqwest::Client::new();

			let request_url = query_to_url(query);
			let req = client.get(request_url).header("accept", "application/dns-message").build();
			let resp = client.execute(req.map_err(|_| DNS_ERR)?).await.map_err(|_| DNS_ERR)?;
			let body = resp.bytes().await.map_err(|_| DNS_ERR)?;

			let mut answer = QueryBuf::new_zeroed(0);
			answer.extend_from_slice(&body[..]);
			match proof_builder.process_response(&answer) {
				Ok(queries) => {
					for query in queries {
						pending_queries.push(query);
					}
				},
				Err(_) => {
					return Err(DNS_ERR);
				},
			}
		}

		let err = "Too many queries required to build proof";
		let proof = proof_builder.finish_proof().map(|(proof, _ttl)| proof).map_err(|()| err)?;

		resolve_proof(&dns_name, proof)
	}

	async fn resolve_lnurl(&self, hrn: &HumanReadableName) -> Result<HrnResolution, &'static str> {
		let init_url = format!("https://{}/.well-known/lnurlp/{}", hrn.domain(), hrn.user());
		let err = "Failed to fetch LN-Address initial well-known endpoint";
		let init: LNURLInitResponse =
			reqwest::get(init_url).await.map_err(|_| err)?.json().await.map_err(|_| err)?;

		if init.tag != "payRequest" {
			return Err("LNURL initial init_responseponse had an incorrect tag value");
		}
		if init.min_sendable > init.max_sendable {
			return Err("LNURL initial init_responseponse had no sendable amounts");
		}

		let err = "LNURL metadata was not in the correct format";
		let metadata: LNURLMetadata = serde_json::from_str(&init.metadata).map_err(|_| err)?;
		let mut recipient_description = None;
		for (ty, value) in metadata.0 {
			if ty == "text/plain" {
				recipient_description = Some(value);
			}
		}
		let expected_description_hash = Sha256::hash(init.metadata.as_bytes()).to_byte_array();
		Ok(HrnResolution::LNURLPay {
			min_value: Amount::from_milli_sats(init.min_sendable),
			max_value: Amount::from_milli_sats(init.max_sendable),
			callback: init.callback,
			expected_description_hash,
			recipient_description,
		})
	}
}

impl HrnResolver for HTTPHrnResolver {
	fn resolve_hrn<'a>(&'a self, hrn: &'a HumanReadableName) -> HrnResolutionFuture<'a> {
		Box::pin(async move {
			// First try to resolve the HRN using BIP 353 DNSSEC proof building
			match self.resolve_dns(hrn).await {
				Ok(r) => Ok(r),
				Err(e) if e == DNS_ERR => {
					// If we got an error that might indicate the recipient doesn't support BIP
					// 353, try LN-Address via LNURL
					self.resolve_lnurl(hrn).await
				},
				Err(e) => Err(e),
			}
		})
	}

	fn resolve_lnurl<'a>(
		&'a self, mut callback: String, amt: Amount, expected_description_hash: [u8; 32],
	) -> LNURLResolutionFuture<'a> {
		Box::pin(async move {
			let err = "LN-Address callback failed";
			if callback.contains('?') {
				write!(&mut callback, "&amount={}", amt.milli_sats()).expect("Write to String");
			} else {
				write!(&mut callback, "?amount={}", amt.milli_sats()).expect("Write to String");
			}
			let callback_response: LNURLCallbackResponse =
				reqwest::get(callback).await.map_err(|_| err)?.json().await.map_err(|_| err)?;

			if !callback_response.routes.is_empty() {
				return Err("LNURL callback response contained a non-empty routes array");
			}

			let invoice = Bolt11Invoice::from_str(&callback_response.pr).map_err(|_| err)?;
			if invoice.amount_milli_satoshis() != Some(amt.milli_sats()) {
				return Err("LNURL callback response contained an invoice with the wrong amount");
			}
			match invoice.description() {
				Bolt11InvoiceDescriptionRef::Hash(hash) => {
					if hash.0.as_byte_array() != &expected_description_hash {
						Err("Incorrect invoice description hash")
					} else {
						Ok(invoice)
					}
				},
				Bolt11InvoiceDescriptionRef::Direct(_) => {
					Err("BOLT 11 invoice resolved via LNURL must have a matching description hash")
				},
			}
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::*;

	#[tokio::test]
	async fn test_dns_via_http_hrn_resolver() {
		let resolver = HTTPHrnResolver;
		let instructions = PaymentInstructions::parse(
			"send.some@satsto.me",
			bitcoin::Network::Bitcoin,
			&resolver,
			true,
		)
		.await
		.unwrap();

		let resolved = if let PaymentInstructions::ConfigurableAmount(instr) = instructions {
			assert_eq!(instr.min_amt(), None);
			assert_eq!(instr.max_amt(), None);

			assert_eq!(instr.pop_callback(), None);
			assert!(instr.bip_353_dnssec_proof().is_some());

			let hrn = instr.human_readable_name().as_ref().unwrap();
			assert_eq!(hrn.user(), "send.some");
			assert_eq!(hrn.domain(), "satsto.me");

			instr.set_amount(Amount::from_sats(100_000), &resolver).await.unwrap()
		} else {
			panic!();
		};

		assert_eq!(resolved.pop_callback(), None);
		assert!(resolved.bip_353_dnssec_proof().is_some());

		let hrn = resolved.human_readable_name().as_ref().unwrap();
		assert_eq!(hrn.user(), "send.some");
		assert_eq!(hrn.domain(), "satsto.me");

		for method in resolved.methods() {
			match method {
				PaymentMethod::LightningBolt11(_) => {
					panic!("Should only have static payment instructions");
				},
				PaymentMethod::LightningBolt12(_) => {},
				PaymentMethod::OnChain { .. } => {},
			}
		}
	}

	#[tokio::test]
	async fn test_http_hrn_resolver() {
		let instructions = PaymentInstructions::parse(
			"lnurltest@bitcoin.ninja",
			bitcoin::Network::Bitcoin,
			&HTTPHrnResolver,
			true,
		)
		.await
		.unwrap();

		let resolved = if let PaymentInstructions::ConfigurableAmount(instr) = instructions {
			// min_amt and max_amt may or may not be set by the LNURL server

			assert_eq!(instr.pop_callback(), None);
			assert!(instr.bip_353_dnssec_proof().is_none());

			let hrn = instr.human_readable_name().as_ref().unwrap();
			assert_eq!(hrn.user(), "lnurltest");
			assert_eq!(hrn.domain(), "bitcoin.ninja");

			instr.set_amount(Amount::from_sats(100_000), &HTTPHrnResolver).await.unwrap()
		} else {
			panic!();
		};

		assert_eq!(resolved.pop_callback(), None);
		assert!(resolved.bip_353_dnssec_proof().is_none());

		let hrn = resolved.human_readable_name().as_ref().unwrap();
		assert_eq!(hrn.user(), "lnurltest");
		assert_eq!(hrn.domain(), "bitcoin.ninja");

		for method in resolved.methods() {
			match method {
				PaymentMethod::LightningBolt11(invoice) => {
					assert_eq!(invoice.amount_milli_satoshis(), Some(100_000_000));
				},
				PaymentMethod::LightningBolt12(_) => panic!("Should only resolve to BOLT 11"),
				PaymentMethod::OnChain(_) => panic!("Should only resolve to BOLT 11"),
			}
		}
	}
}
