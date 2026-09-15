//! A [`HrnResolver`] which uses lightning onion messages and DNSSEC proofs to request DNS
//! resolution directly from untrusted lightning nodes, providing privacy through onion routing.

use std::boxed::Box;
use std::collections::HashMap;
use std::future::Future;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll, Waker};
use std::vec::Vec;

use lightning::blinded_path::message::DNSResolverContext;
use lightning::ln::channelmanager::PaymentId;
use lightning::onion_message::dns_resolution::{
	DNSResolverMessage, DNSResolverMessageHandler, DNSSECError, DNSSECProof, DNSSECQuery,
	OMNameResolver,
};
use lightning::onion_message::messenger::{
	Destination, MessageSendInstructions, Responder, ResponseInstruction,
};
use lightning::routing::gossip::NetworkGraph;
use lightning::sign::EntropySource;
use lightning::util::logger::Logger;

use crate::hrn_resolution::{
	HrnResolution, HrnResolutionFuture, HrnResolver, HumanReadableName, LNURLResolutionFuture,
};
use crate::Amount;

struct OsRng;
impl EntropySource for OsRng {
	fn get_secure_random_bytes(&self) -> [u8; 32] {
		let mut res = [0; 32];
		getrandom::fill(&mut res).expect("Fetching system randomness should always succeed");
		res
	}
}

struct ChannelState {
	waker: Option<Waker>,
	result: Option<Result<HrnResolution, &'static str>>,
}

struct ChannelSend(Arc<Mutex<ChannelState>>);

impl ChannelSend {
	fn complete(self, result: Result<HrnResolution, &'static str>) {
		let mut state = self.0.lock().unwrap();
		state.result = Some(result);
		if let Some(waker) = state.waker.take() {
			waker.wake();
		}
	}

	fn receiver_alive(&self) -> bool {
		Arc::strong_count(&self.0) > 1
	}
}

struct ChannelRecv(Arc<Mutex<ChannelState>>);

impl Future for ChannelRecv {
	type Output = Result<HrnResolution, &'static str>;
	fn poll(
		self: Pin<&mut Self>, context: &mut Context,
	) -> Poll<Result<HrnResolution, &'static str>> {
		let mut state = self.0.lock().unwrap();
		if let Some(res) = state.result.take() {
			debug_assert!(state.waker.is_none());
			Poll::Ready(res)
		} else {
			state.waker = Some(context.waker().clone());
			Poll::Pending
		}
	}
}

fn channel() -> (ChannelSend, ChannelRecv) {
	let state = Arc::new(Mutex::new(ChannelState { waker: None, result: None }));
	(ChannelSend(Arc::clone(&state)), ChannelRecv(state))
}

/// A [`HrnResolver`] which uses lightning onion messages and DNSSEC proofs to request DNS
/// resolution directly from untrusted lightning nodes, providing privacy through onion routing.
///
/// This implements LDK's [`DNSResolverMessageHandler`], which it uses to send onion messages and
/// process response messages.
///
/// Note that because this implementation does not assume an async runtime, queries which are not
/// responded to *may hang forever*. You must always wrap resolution futures to ensure they time
/// out properly, eg via `tokio::time::timeout`.
///
/// Note that after a query begines, [`PeerManager::process_events`] should be called to ensure the
/// query message goes out in a timely manner. You can call [`Self::register_post_queue_action`] to
/// have this happen automatically.
///
/// [`PeerManager::process_events`]: lightning::ln::peer_handler::PeerManager::process_events
pub struct LDKOnionMessageDNSSECHrnResolver<N: Deref<Target = NetworkGraph<L>>, L: Deref>
where
	L::Target: Logger,
{
	network_graph: N,
	resolver: OMNameResolver,
	next_id: AtomicUsize,
	pending_resolutions: Mutex<HashMap<HumanReadableName, Vec<(PaymentId, ChannelSend)>>>,
	message_queue: Mutex<Vec<(DNSResolverMessage, MessageSendInstructions)>>,
	pm_event_poker: RwLock<Option<Box<dyn Fn() + Send + Sync>>>,
}

impl<N: Deref<Target = NetworkGraph<L>>, L: Deref> LDKOnionMessageDNSSECHrnResolver<N, L>
where
	L::Target: Logger,
{
	/// Constructs a new [`LDKOnionMessageDNSSECHrnResolver`].
	///
	/// See the struct-level documentation for more info.
	pub fn new(network_graph: N) -> Self {
		Self {
			network_graph,
			next_id: AtomicUsize::new(0),
			// TODO: Swap for `new_without_expiry_validation` when we upgrade to LDK 0.2
			resolver: OMNameResolver::new(0, 0),
			pending_resolutions: Mutex::new(HashMap::new()),
			message_queue: Mutex::new(Vec::new()),
			pm_event_poker: RwLock::new(None),
		}
	}

	/// Sets a callback which is called any time a new resolution begins and a message is available
	/// to be sent. This should generally call [`PeerManager::process_events`].
	///
	/// [`PeerManager::process_events`]: lightning::ln::peer_handler::PeerManager::process_events
	pub fn register_post_queue_action(&self, callback: Box<dyn Fn() + Send + Sync>) {
		*self.pm_event_poker.write().unwrap() = Some(callback);
	}

	fn fail_resolutions(&self, failed: Vec<(HumanReadableName, PaymentId)>) {
		let mut pending_resolutions = self.pending_resolutions.lock().unwrap();
		for (name, payment_id) in failed {
			if let Some(requests) = pending_resolutions.get_mut(&name) {
				if let Some(index) = requests.iter().position(|(id, _)| *id == payment_id) {
					let (_, send) = requests.remove(index);
					send.complete(Err("Failed to resolve HRN using DNSSEC"));
				}
				if requests.is_empty() {
					pending_resolutions.remove(&name);
				}
			}
		}
	}

	fn init_resolve_hrn<'a>(
		&'a self, hrn: &HumanReadableName,
	) -> Result<ChannelRecv, &'static str> {
		#[cfg(feature = "std")]
		{
			use std::time::SystemTime;
			let clock_err =
				"DNSSEC validation relies on having a correct system clock. It is currently set before 1970.";
			let now =
				SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_err(|_| clock_err)?;
			// Use `now / 60` as the block height to expire pending requests after 1-2 minutes.
			self.resolver.new_best_block((now.as_secs() / 60) as u32, now.as_secs() as u32);
		}

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

		let counter = self.next_id.fetch_add(1, Ordering::Relaxed) as u64;
		let mut payment_id = [0; 32];
		payment_id[..8].copy_from_slice(&counter.to_ne_bytes());
		let payment_id = PaymentId(payment_id);

		let err = "The provided HRN did not fit in a DNS request";
		let messages = self
			.resolver
			.initiate_resolution(payment_id, *hrn, dns_resolvers, &OsRng)
			.map_err(|_| err)?;

		let (send, recv) = channel();
		{
			let mut pending_resolutions = self.pending_resolutions.lock().unwrap();
			let senders = pending_resolutions.entry(*hrn).or_insert_with(Vec::new);
			senders.push((payment_id, send));

			// If we're running in no-std, we won't expire lookups with the time updates above, so walk
			// the pending resolution list and expire them here.
			pending_resolutions.retain(|_name, resolutions| {
				resolutions.retain(|(_payment_id, resolution)| {
					let has_receiver = resolution.receiver_alive();
					if !has_receiver {
						// TODO: Once LDK 0.2 ships, expire the pending resolution in the resolver:
						// self.resolver.expire_pending_resolution(name, payment_id);
					}
					has_receiver
				});
				!resolutions.is_empty()
			});
		}

		self.message_queue.lock().unwrap().extend(messages);

		let callback = self.pm_event_poker.read().unwrap();
		if let Some(callback) = &*callback {
			callback();
		}

		Ok(recv)
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
		match self.resolver.handle_dnssec_proof_for_uri(msg.clone(), context) {
			Ok((resolved, res)) => {
				let mut pending_resolutions = self.pending_resolutions.lock().unwrap();
				for (name, _payment_id) in resolved {
					if let Some(requests) = pending_resolutions.remove(&name) {
						for (_id, send) in requests {
							send.complete(Ok(HrnResolution::DNSSEC {
								proof: Some(msg.proof.clone()),
								result: res.clone(),
							}));
						}
					}
				}
			},
			Err(failed) => self.fail_resolutions(failed),
		}
	}

	fn handle_dnssec_error(&self, msg: DNSSECError, context: DNSResolverContext) {
		self.fail_resolutions(self.resolver.handle_dnssec_error(msg, context));
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
		match self.init_resolve_hrn(hrn) {
			Err(e) => Box::pin(async move { Err(e) }),
			Ok(recv) => Box::pin(recv),
		}
	}

	fn resolve_lnurl<'a>(&'a self, _url: &'a str) -> HrnResolutionFuture<'a> {
		let err = "DNS resolver does not support LNURL resolution";
		Box::pin(async move { Err(err) })
	}

	fn resolve_lnurl_to_invoice<'a>(
		&'a self, _: String, _: Amount, _: [u8; 32],
	) -> LNURLResolutionFuture<'a> {
		let err = "resolve_lnurl_to_invoice shouldn't be called when we don't resolve LNURL";
		debug_assert!(false, "{err}");
		Box::pin(async move { Err(err) })
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::*;

	use std::net::ToSocketAddrs;

	use bitcoin::hex::FromHex;
	use bitcoin::secp256k1::PublicKey;

	use lightning::blinded_path::NodeIdLookUp;
	use lightning::ln::peer_handler::{
		ErroringMessageHandler, IgnoringMessageHandler, MessageHandler, PeerManager,
	};
	use lightning::onion_message::messenger::{DefaultMessageRouter, OnionMessenger};
	use lightning::routing::gossip::{NodeId, P2PGossipSync};
	use lightning::routing::utxo::UtxoLookup;
	use lightning::sign::KeysManager;
	use lightning::util::logger::Record;

	struct TestLogger;
	impl Logger for TestLogger {
		fn log(&self, r: Record) {
			eprintln!("{}", r.args);
		}
	}

	struct NoPeers;
	impl NodeIdLookUp for NoPeers {
		fn next_node_id(&self, _scid: u64) -> Option<PublicKey> {
			None
		}
	}

	#[tokio::test]
	async fn dns_errors_wait_for_all_resolvers_and_preserve_other_requests() {
		use lightning::blinded_path::message::MessageContext;
		let graph = Arc::new(NetworkGraph::new(Network::Bitcoin, &TestLogger));
		let resolver = LDKOnionMessageDNSSECHrnResolver::new(graph);
		let hrn = HumanReadableName::from_encoded("test@example.com").unwrap();
		let signer = KeysManager::new(&[42; 32], 0, 0, true, &TestLogger);
		let node_id = PublicKey::from_secret_key(
			&bitcoin::secp256k1::Secp256k1::new(),
			&signer.get_node_secret_key(),
		);
		let destinations = vec![Destination::Node(node_id), Destination::Node(node_id)];
		let mut receivers = Vec::new();
		let mut queries = Vec::new();
		for id in [PaymentId([1; 32]), PaymentId([2; 32])] {
			queries.push(
				resolver
					.resolver
					.initiate_resolution(id, hrn, destinations.clone(), &OsRng)
					.unwrap(),
			);
			let (send, recv) = channel();
			resolver.pending_resolutions.lock().unwrap().entry(hrn).or_default().push((id, send));
			receivers.push(recv);
		}
		let first_queries = queries.remove(0);
		let contexts: Vec<_> = first_queries
			.into_iter()
			.map(|(query, instructions)| {
				let DNSResolverMessage::DNSSECQuery(query) = query else {
					panic!("expected query")
				};
				let MessageSendInstructions::WithReplyPath {
					context: MessageContext::DNSResolver(context),
					..
				} = instructions
				else {
					panic!("expected reply context")
				};
				(query.0, context)
			})
			.collect();
		assert_ne!(contexts[0].1, contexts[1].1);
		let error = DNSSECError { name: contexts[0].0.clone(), definitely_unresolvable: false };
		resolver.handle_dnssec_error(error.clone(), contexts[0].1.clone());
		assert!(receivers[0].0.lock().unwrap().result.is_none());
		// A duplicate error must not count as the other resolver failing.
		resolver.handle_dnssec_error(error.clone(), contexts[0].1.clone());
		assert!(receivers[0].0.lock().unwrap().result.is_none());
		resolver.handle_dnssec_error(error, contexts[1].1.clone());
		assert!(receivers.remove(0).await.is_err());
		assert!(receivers[0].0.lock().unwrap().result.is_none());
		assert_eq!(resolver.pending_resolutions.lock().unwrap()[&hrn].len(), 1);
		// Invalid proofs should also finish the request once every query fails.
		for (query, instructions) in queries.remove(0) {
			let DNSResolverMessage::DNSSECQuery(query) = query else { panic!("expected query") };
			let MessageSendInstructions::WithReplyPath {
				context: MessageContext::DNSResolver(context),
				..
			} = instructions
			else {
				panic!("expected reply context")
			};
			resolver.handle_dnssec_proof(DNSSECProof { name: query.0, proof: Vec::new() }, context);
		}
		assert!(receivers.remove(0).await.is_err());
		assert!(resolver.pending_resolutions.lock().unwrap().is_empty());
	}

	#[tokio::test]
	async fn test_dns_om_hrn_resolver() {
		let graph = Arc::new(NetworkGraph::new(Network::Bitcoin, &TestLogger));
		let resolver = Arc::new(LDKOnionMessageDNSSECHrnResolver::new(Arc::clone(&graph)));
		let signer =
			Arc::new(KeysManager::new(&OsRng.get_secure_random_bytes(), 0, 0, true, &TestLogger));
		let message_router = Arc::new(DefaultMessageRouter::new(Arc::clone(&graph), &OsRng));
		let messenger = Arc::new(OnionMessenger::new(
			&OsRng,
			Arc::clone(&signer),
			&TestLogger,
			&NoPeers,
			message_router,
			&IgnoringMessageHandler {},
			&IgnoringMessageHandler {},
			Arc::clone(&resolver),
			&IgnoringMessageHandler {},
		));
		let no_utxos = None::<&(dyn UtxoLookup + Sync + Send)>;
		let handlers = MessageHandler {
			chan_handler: Arc::new(ErroringMessageHandler::new()),
			route_handler: Arc::new(P2PGossipSync::new(Arc::clone(&graph), no_utxos, &TestLogger)),
			onion_message_handler: Arc::clone(&messenger),
			custom_message_handler: &IgnoringMessageHandler {},
			send_only_message_handler: &IgnoringMessageHandler {},
		};
		let rand = OsRng.get_secure_random_bytes();
		let peer_manager =
			Arc::new(PeerManager::new(handlers, 0, &rand, &TestLogger, Arc::clone(&signer)));

		// Maintain a connection to a static LDK node which we know will do DNS resolutions for us.
		let their_id_hex = "03db10aa09ff04d3568b0621750794063df401e6853c79a21a83e1a3f3b5bfb0c8";
		let their_id = PublicKey::from_slice(&Vec::<u8>::from_hex(their_id_hex).unwrap()).unwrap();
		let addr = "ldk-ln-node.bitcoin.ninja:9735".to_socket_addrs().unwrap().next().unwrap();
		let connect_pm = Arc::clone(&peer_manager);
		tokio::spawn(async move {
			loop {
				lightning_net_tokio::connect_outbound(Arc::clone(&connect_pm), their_id, addr)
					.await
					.unwrap()
					.await;
			}
		});

		let pm_reference = Arc::clone(&peer_manager);
		tokio::spawn(async move {
			pm_reference.process_events();
			tokio::time::sleep(Duration::from_micros(10)).await;
		});

		let their_node_id = NodeId::from_pubkey(&their_id);
		loop {
			{
				let graph = graph.read_only();
				let have_announcement =
					graph.nodes().get(&their_node_id).map(|node| node.announcement_info.is_some());
				if have_announcement.unwrap_or(false) {
					break;
				}
			}
			tokio::time::sleep(Duration::from_millis(5)).await;
			peer_manager.process_events();
		}

		let instructions = PaymentInstructions::parse(
			"send.some@satsto.me",
			bitcoin::Network::Bitcoin,
			&*resolver,
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

			instr.set_amount(Amount::from_sats(100_000).unwrap(), &*resolver).await.unwrap()
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
}
