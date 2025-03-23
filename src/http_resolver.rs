//! A [`HrnResolver`] which uses `reqwest` and `dns.google` (8.8.8.8) to resolve Human Readable
//! Names into bitcoin payment instructions.

use std::boxed::Box;

use serde::Deserialize;

use dnssec_prover::query::{ProofBuilder, QueryBuf};
use dnssec_prover::rr::{Name, TXT_TYPE};

use crate::dnssec_utils::resolve_proof;
use crate::{HrnResolution, HrnResolutionFuture, HrnResolver, HumanReadableName};

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
	#[serde(rename = "metadata")]
	_metadata: String,
	tag: String,
}

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
					return Err("DNS resolution failed");
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

		// LUD-6 requires that we specify a fixed amount here, but we're just trying to resolve the
		// HRN into payment instructions, not use a fixed amount, so we leave the amount request
		// out and hope the server gives us an amount-less invoice.
		let err = "LN-Address callback failed";
		let callback_response: LNURLCallbackResponse =
			reqwest::get(init.callback).await.map_err(|_| err)?.json().await.map_err(|_| err)?;

		if !callback_response.routes.is_empty() {
			return Err("LNURL callback response contained a non-empty routes array");
		}

		// Technically we're supposed to verify init.metadata matches the BOLT 11 invoice
		// description hash, but given we're not storing the metadata anywhere, there's not really
		// much point.
		Ok(HrnResolution { proof: None, result: callback_response.pr })
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
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::*;

	#[tokio::test]
	async fn test_http_hrn_resolver() {
		let instructions = PaymentInstructions::parse(
			"send.some@satsto.me",
			bitcoin::Network::Bitcoin,
			HTTPHrnResolver,
			true,
		)
		.await
		.unwrap();

		assert_eq!(instructions.max_amount(), None);
		assert_eq!(instructions.pop_callback(), None);
		assert!(instructions.bip_353_dnssec_proof().is_some());

		let hrn = instructions.human_readable_name().as_ref().unwrap();
		assert_eq!(hrn.user(), "send.some");
		assert_eq!(hrn.domain(), "satsto.me");

		for method in instructions.methods() {
			assert_eq!(method.amount(), None);
			match method {
				PaymentMethod::LightningBolt11(_) => {
					panic!("Should only have static payment instructions");
				},
				PaymentMethod::LightningBolt12(_) => {},
				PaymentMethod::OnChain { .. } => {},
			}
		}
	}
}
