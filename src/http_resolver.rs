//! A [`HrnResolver`] which uses `reqwest` and `dns.google` (8.8.8.8) to resolve Human Readable
//! Names into bitcoin payment instructions.

use std::boxed::Box;

use dnssec_prover::query::{ProofBuilder, QueryBuf};
use dnssec_prover::rr::{Name, RR, TXT_TYPE};
use dnssec_prover::ser::parse_rr_stream;
use dnssec_prover::validation::verify_rr_stream;

use crate::{HrnResolution, HrnResolutionFuture, HrnResolver, HumanReadableName};

const DOH_ENDPOINT: &'static str = "https://dns.google/dns-query?dns=";

/// An [`HrnResolver`] which uses `reqwest` and `dns.google` (8.8.8.8) to resolve Human Readable
/// Names into bitcoin payment instructions.
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

impl HTTPHrnResolver {
	async fn resolve_dns(&self, hrn: &HumanReadableName) -> Result<HrnResolution, &'static str> {
		let dns_name =
			Name::try_from(format!("{}.user._bitcoin-payment.{}.", hrn.user(), hrn.domain()))
				.map_err(|_| "The provided HRN was too long to fit in a DNS name")?;
		let (mut proof_builder, initial_query) = ProofBuilder::new(&dns_name, TXT_TYPE);
		let mut pending_queries = vec![initial_query];

		while let Some(query) = pending_queries.pop() {
			let client = reqwest::Client::new();

			let err = "DNS Request to dns.google failed";

			let request_url = query_to_url(query);
			let req = client.get(request_url).header("accept", "application/dns-message").build();
			let resp = client.execute(req.map_err(|_| err)?).await.map_err(|_| err)?;
			let body = resp.bytes().await.map_err(|_| err)?;

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

		let rrs = parse_rr_stream(&proof)
			.map_err(|()| "DNS Proof Builder somehow generated an invalid proof")?;
		let verified_rrs = verify_rr_stream(&rrs).map_err(|_| "DNSSEC signatures were invalid")?;
		let resolved_rrs = verified_rrs.resolve_name(&dns_name);

		let mut result = None;
		for rr in resolved_rrs {
			match rr {
				RR::Txt(txt) => {
					if result.is_some() {
						return Err("Multiple TXT records existed for the HRN, which is invalid");
					}
					result = Some(txt.data.as_vec());
				},
				_ => {},
			}
		}
		if let Some(res) = result {
			let result =
				String::from_utf8(res).map_err(|_| "TXT record contained an invalid string")?;
			Ok(HrnResolution { proof: Some(proof), result })
		} else {
			Err("No validated TXT record found")
		}
	}
}

impl HrnResolver for HTTPHrnResolver {
	fn resolve_hrn<'a>(&'a self, hrn: &'a HumanReadableName) -> HrnResolutionFuture<'a> {
		Box::pin(async move {
			// First try to resolve the HRN using BIP 353 DNSSEC proof building
			self.resolve_dns(hrn).await
			//TODO: Then try to resolve using LN-Address/LNURL
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::*;

	#[tokio::test]
	async fn test_http_hrn_resolver() {
		let instructions = PaymentInstructions::parse_payment_instructions(
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
