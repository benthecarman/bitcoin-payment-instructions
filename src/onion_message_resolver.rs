//! A [`HrnResolver`] which uses lightning onion messages and DNSSEC proofs to request DNS
//! resolution directly from untrusted lightning nodes, providing privacy through onion routing.

use std::boxed::Box;
use std::ops::Deref;
use std::sync::Mutex;
use std::vec::Vec;

use lightning::blinded_path::message::DNSResolverContext;
use lightning::ln::channelmanager::PaymentId;
use lightning::onion_message::dns_resolution::{
	DNSResolverMessage, DNSResolverMessageHandler, DNSSECProof, DNSSECQuery, HumanReadableName,
	OMNameResolver,
};
use lightning::onion_message::messenger::{
	Destination, MessageSendInstructions, Responder, ResponseInstruction,
};
use lightning::routing::gossip::NetworkGraph;
use lightning::sign::EntropySource;
use lightning::util::logger::Logger;

use crate::{HrnResolution, HrnResolutionFuture, HrnResolver};

struct OsRng;
impl EntropySource for OsRng {
	fn get_secure_random_bytes(&self) -> [u8; 32] {
		let mut res = [0; 32];
		getrandom::fill(&mut res).expect("Fetching system randomness should always succeed");
		res
	}
}

/// A [`HrnResolver`] which uses lightning onion messages and DNSSEC proofs to request DNS
/// resolution directly from untrusted lightning nodes, providing privacy through onion routing.
///
/// NOTE THAT THIS DOES NOT YET WORK AND IS NOT YET FULLY IMPLEMENTED
pub struct LDKOnionMessageDNSSECHrnResolver<N: Deref<Target = NetworkGraph<L>>, L: Deref>
where
	L::Target: Logger,
{
	network_graph: N,
	resolver: OMNameResolver,
	message_queue: Mutex<Vec<(DNSResolverMessage, MessageSendInstructions)>>,
}

impl<N: Deref<Target = NetworkGraph<L>>, L: Deref> LDKOnionMessageDNSSECHrnResolver<N, L>
where
	L::Target: Logger,
{
	async fn resolve_hrn(&self, hrn: &HumanReadableName) -> Result<HrnResolution, &'static str> {
		let mut dns_resolvers = Vec::new();
		for (node_id, node) in self.network_graph.read_only().nodes().unordered_iter() {
			if let Some(info) = &node.announcement_info {
				// Sadly, 31 nodes currently squat on the DNS Resolver feature bit
				// without speaking it.
				// Its unclear why they're doing so, but none of them currently
				// also have the onion messaging feature bit set, so here we check
				// for both.
				let supports_dns = info.features().supports_dns_resolution();
				let supports_om = info.features().supports_onion_messages();
				if supports_dns && supports_om {
					if let Ok(pubkey) = node_id.as_pubkey() {
						dns_resolvers.push(Destination::Node(pubkey));
					}
				}
			}
			if dns_resolvers.len() > 5 {
				break;
			}
		}
		if dns_resolvers.is_empty() {
			return Err(
				"Failed to find any DNS resolving nodes, check your network graph is synced",
			);
		}
		let payment_id = PaymentId(OsRng.get_secure_random_bytes());
		let err = "The provided HRN did not fit in a DNS request";
		let (query, _context) =
			self.resolver.resolve_name(payment_id, hrn.clone(), &OsRng).map_err(|_| err)?;
		// XXX: need reply path to us here (https://github.com/lightningdevkit/rust-lightning/issues/3669)
		// let reply_path = new_reply_path(context)

		let mut queue = self.message_queue.lock().unwrap();
		for destination in dns_resolvers {
			let instructions = MessageSendInstructions::WithoutReplyPath { destination };
			queue.push((DNSResolverMessage::DNSSECQuery(query.clone()), instructions));
		}
		// XXX: now we need to someone build a future that lets us store the polling context in
		// LDKOnionMessageDNSSECHrnResolver, then once we get the response in handle_dnssec_proof
		// we should wake that context and return the result!
		Err("unimplemented!")
	}
}

impl<N: Deref<Target = NetworkGraph<L>>, L: Deref> DNSResolverMessageHandler
	for LDKOnionMessageDNSSECHrnResolver<N, L>
where
	L::Target: Logger,
{
	fn handle_dnssec_query(
		&self, _: DNSSECQuery, _: Option<Responder>,
	) -> Option<(DNSResolverMessage, ResponseInstruction)> {
		None
	}

	fn handle_dnssec_proof(&self, msg: DNSSECProof, context: DNSResolverContext) {
		let results = self.resolver.handle_dnssec_proof_for_uri(msg, context);
		if let Some((resolved, _res)) = results {
			for _resolved in resolved {
				// XXX: wake context
			}
		}
	}

	fn release_pending_messages(&self) -> Vec<(DNSResolverMessage, MessageSendInstructions)> {
		std::mem::take(&mut self.message_queue.lock().unwrap())
	}
}

impl<N: Deref<Target = NetworkGraph<L>> + Sync, L: Deref> HrnResolver
	for LDKOnionMessageDNSSECHrnResolver<N, L>
where
	L::Target: Logger,
{
	fn resolve_hrn<'a>(&'a self, hrn: &'a HumanReadableName) -> HrnResolutionFuture<'a> {
		Box::pin(async move { self.resolve_hrn(hrn).await })
	}
}
