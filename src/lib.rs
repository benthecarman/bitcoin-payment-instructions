//! These days, there are many possible ways to communicate Bitcoin payment instructions.
//! This crate attempts to unify them into a simple parser which can read text provided directly by
//! a payer or via a QR code scan/URI open and convert it into payment instructions.
//!
//! See the [`PaymentInstructions`] type for the supported instruction formats.
//!
//! This crate doesn't actually help you *pay* these instructions, but provides a unified way to
//! parse them.

#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
extern crate core;

use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::str::FromStr;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use core::future::Future;
use core::pin::Pin;
use core::time::Duration;

use bitcoin::{address, Address, Network};
use lightning::offers::offer::{self, Offer};
use lightning::offers::parse::Bolt12ParseError;
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescriptionRef, ParseOrSemanticError};

pub use lightning::onion_message::dns_resolution::HumanReadableName;

#[cfg(feature = "std")]
mod dnssec_utils;

#[cfg(feature = "std")]
pub mod dns_resolver;

#[cfg(feature = "http")]
pub mod http_resolver;

pub mod amount;

pub mod receive;

use amount::Amount;

/// A method which can be used to make a payment
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PaymentMethod {
	/// A payment using lightning as descibred by the given BOLT 11 invoice.
	LightningBolt11(Bolt11Invoice),
	/// A payment using lightning as descibred by the given BOLT 12 offer.
	LightningBolt12(Offer),
	/// A payment directly on-chain to the specified address.
	OnChain {
		/// The amount which this payment method requires payment for.
		///
		/// * For instructions extracted from BIP 321 bitcoin: URIs this is the `amount` parameter.
		/// * For the fallback address from a lightning BOLT 11 invoice this is the invoice's
		///   amount, rounded up to the nearest whole satoshi.
		amount: Option<Amount>,
		/// The address to which payment can be made.
		address: Address,
	},
}

impl PaymentMethod {
	/// The amount this payment method requires payment for.
	///
	/// If `None` for non-BOLT 12 payments, any amount can be paid.
	///
	/// For Lightning BOLT 12 offers, the requested amount may be denominated in an alternative
	/// currency, requiring currency conversion and negotiatin while paying. In such a case, `None`
	/// will be returned. See [`Offer::amount`] and LDK's offer payment logic for more info.
	pub fn amount(&self) -> Option<Amount> {
		match self {
			PaymentMethod::LightningBolt11(invoice) => {
				invoice.amount_milli_satoshis().map(Amount::from_milli_sats)
			},
			PaymentMethod::LightningBolt12(offer) => match offer.amount() {
				Some(offer::Amount::Bitcoin { amount_msats }) => {
					Some(Amount::from_milli_sats(amount_msats))
				},
				Some(offer::Amount::Currency { .. }) => None,
				None => None,
			},
			PaymentMethod::OnChain { amount, .. } => *amount,
		}
	}
}

/// Parsed payment instructions representing a set of possible ways to pay, as well as some
/// associated metadata.
///
/// It supports:
///  * BIP 321 bitcoin: URIs
///  * Lightning BOLT 11 invoices (optionally with the lightning: URI prefix)
///  * Lightning BOLT 12 offers
///  * On-chain addresses
///  * BIP 353 human-readable names in the name@domain format.
///  * LN-Address human-readable names in the name@domain format.
#[derive(PartialEq, Eq, Debug)]
pub struct PaymentInstructions {
	recipient_description: Option<String>,
	methods: Vec<PaymentMethod>,
	pop_callback: Option<String>,
	hrn: Option<HumanReadableName>,
	hrn_proof: Option<Vec<u8>>,
}

/// The maximum amount requested that we will allow individual payment methods to differ in
/// satoshis.
///
/// If any [`PaymentMethod::amount`] differs from another by more than this amount, we will
/// consider it a [`ParseError::InconsistentInstructions`].
pub const MAX_AMOUNT_DIFFERENCE: Amount = Amount::from_sats(100);

/// An error when parsing payment instructions into [`PaymentInstructions`].
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub enum ParseError {
	/// An invalid lightning BOLT 11 invoice was encountered
	InvalidBolt11(ParseOrSemanticError),
	/// An invalid lightning BOLT 12 offer was encountered
	InvalidBolt12(Bolt12ParseError),
	/// An invalid on-chain address was encountered
	InvalidOnChain(address::ParseError),
	/// The payment instructions encoded instructions for a network other than the one specified.
	WrongNetwork,
	/// Different parts of the payment instructions were inconsistent.
	///
	/// A developer-readable error string is provided, though you may or may not wish to provide
	/// this directly to users.
	InconsistentInstructions(&'static str),
	/// The instructions were invalid due to a semantic error.
	///
	/// A developer-readable error string is provided, though you may or may not wish to provide
	/// this directly to users.
	InvalidInstructions(&'static str),
	/// The payment instructions did not appear to match any known form of payment instructions.
	UnknownPaymentInstructions,
	/// The BIP 321 bitcoin: URI included unknown required parameter(s)
	UnknownRequiredParameter,
	/// The call to [`HrnResolver::resolve_hrn`] failed with the contained error.
	HrnResolutionError(&'static str),
	/// The payment instructions have expired and are no longer payable.
	InstructionsExpired,
}

impl PaymentInstructions {
	/// The maximum amount any payment instruction requires payment for.
	///
	/// If `None`, any amount can be paid.
	///
	/// Note that we may allow different [`Self::methods`] to have slightly different amounts (e.g.
	/// if a recipient wishes to be paid more for on-chain payments to offset their future fees),
	/// but only up to [`MAX_AMOUNT_DIFFERENCE`].
	pub fn max_amount(&self) -> Option<Amount> {
		let mut max_amt = None;
		for method in self.methods() {
			if let Some(amt) = method.amount() {
				if max_amt.is_none() || max_amt.unwrap() < amt {
					max_amt = Some(amt);
				}
			}
		}
		max_amt
	}

	/// The amount which the payment instruction requires payment for when paid over lightning.
	///
	/// We require that all lightning payment methods in payment instructions require an identical
	/// amount for payment, and thus if this method returns `None` it indicates either:
	///  * no lightning payment instructions exist,
	///  * there is no required amount and any amount can be paid
	///  * the only lightning payment instructions are for a BOLT 12 offer denominated in a
	///    non-Bitcoin currency.
	pub fn ln_payment_amount(&self) -> Option<Amount> {
		for method in self.methods() {
			match method {
				PaymentMethod::LightningBolt11(_) | PaymentMethod::LightningBolt12(_) => {
					return method.amount();
				},
				PaymentMethod::OnChain { .. } => {},
			}
		}
		None
	}

	/// The amount which the payment instruction requires payment for when paid on-chain.
	///
	/// There is no way to encode different payment amounts for multiple on-chain formats
	/// currently, and as such all on-chain [`PaymentMethod`]s will contain the same
	/// [`PaymentMethod::amount`].
	pub fn onchain_payment_amount(&self) -> Option<Amount> {
		for method in self.methods() {
			match method {
				PaymentMethod::LightningBolt11(_) | PaymentMethod::LightningBolt12(_) => {},
				PaymentMethod::OnChain { .. } => {
					return method.amount();
				},
			}
		}
		None
	}

	/// The list of [`PaymentMethod`]s.
	pub fn methods(&self) -> &[PaymentMethod] {
		&self.methods
	}

	/// A recipient-provided description of the payment instructions.
	///
	/// This may be:
	///  * the `label` or `message` parameter in a BIP 321 bitcoin: URI
	///  * the `description` field in a lightning BOLT 11 invoice
	///  * the `description` field in a lightning BOLT 12 offer
	pub fn recipient_description(&self) -> Option<&str> {
		self.recipient_description.as_ref().map(|d| d.as_str())
	}

	/// Fetches the proof-of-payment callback URI.
	///
	/// Once a payment has been completed, the proof-of-payment (hex-encoded payment preimage for a
	/// lightning BOLT 11 invoice, raw transaction serialized in hex for on-chain payments,
	/// not-yet-defined for lightning BOLT 12 invoices) must be appended to this URI and the URI
	/// opened with the default system URI handler.
	pub fn pop_callback(&self) -> Option<&str> {
		self.pop_callback.as_ref().map(|c| c.as_str())
	}

	/// Fetches the [`HumanReadableName`] which was resolved, if the resolved payment instructions
	/// were for a Human Readable Name.
	pub fn human_readable_name(&self) -> &Option<HumanReadableName> {
		&self.hrn
	}

	/// Fetches the BIP 353 DNSSEC proof which was used to resolve these payment instructions, if
	/// they were resolved from a HumanReadable Name using BIP 353.
	///
	/// This proof should be included in any PSBT output (as type `PSBT_OUT_DNSSEC_PROOF`)
	/// generated using these payment instructions.
	///
	/// It should also be stored to allow us to later prove that this payment was made to
	/// [`Self::human_readable_name`].
	pub fn bip_353_dnssec_proof(&self) -> &Option<Vec<u8>> {
		&self.hrn_proof
	}
}

fn check_expiry(_expiry: Duration) -> Result<(), ParseError> {
	#[cfg(feature = "std")]
	{
		use std::time::SystemTime;
		if let Ok(now) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
			if now > _expiry {
				return Err(ParseError::InstructionsExpired);
			}
		}
	}
	Ok(())
}

fn instructions_from_bolt11(
	invoice: Bolt11Invoice, network: Network,
) -> Result<(Option<String>, impl Iterator<Item = PaymentMethod>), ParseError> {
	if invoice.network() != network {
		return Err(ParseError::WrongNetwork);
	}
	if let Some(expiry) = invoice.expires_at() {
		check_expiry(expiry)?;
	}

	let fallbacks = invoice.fallback_addresses().into_iter();
	// For the on-chain amounts, always round up to the next whole satoshi
	let amount = invoice.amount_milli_satoshis().map(|a| Amount::from_sats((a + 999) / 1000));
	let fallbacks = fallbacks.map(move |address| PaymentMethod::OnChain { address, amount });

	if let Bolt11InvoiceDescriptionRef::Direct(desc) = invoice.description() {
		Ok((
			Some(desc.as_inner().0.clone()),
			Some(PaymentMethod::LightningBolt11(invoice)).into_iter().chain(fallbacks),
		))
	} else {
		Ok((None, Some(PaymentMethod::LightningBolt11(invoice)).into_iter().chain(fallbacks)))
	}
}

// What str.split_once() should do...
fn split_once(haystack: &str, needle: char) -> (&str, Option<&str>) {
	haystack.split_once(needle).map(|(a, b)| (a, Some(b))).unwrap_or((haystack, None))
}

fn un_percent_encode(encoded: &str) -> Result<String, ParseError> {
	let mut res = Vec::with_capacity(encoded.len());
	let mut iter = encoded.bytes();
	let err = "A Proof of Payment URI was not properly %-encoded in a BIP 321 bitcoin: URI";
	while let Some(b) = iter.next() {
		if b == b'%' {
			let high = iter.next().ok_or(ParseError::InvalidInstructions(err))?;
			let low = iter.next().ok_or(ParseError::InvalidInstructions(err))?;
			if !high.is_ascii_digit() || !low.is_ascii_digit() {
				return Err(ParseError::InvalidInstructions(err));
			}
			res.push(((high - b'0') << 4) | (low - b'0'));
		} else {
			res.push(b);
		}
	}
	String::from_utf8(res).map_err(|_| ParseError::InvalidInstructions(err))
}

#[test]
fn test_un_percent_encode() {
	assert_eq!(un_percent_encode("%20").unwrap(), " ");
	assert_eq!(un_percent_encode("42%20 ").unwrap(), "42  ");
	assert!(un_percent_encode("42%2").is_err());
	assert!(un_percent_encode("42%2a").is_err());
}

fn parse_resolved_instructions(
	instructions: &str, network: Network, supports_proof_of_payment_callbacks: bool,
	hrn: Option<HumanReadableName>, hrn_proof: Option<Vec<u8>>,
) -> Result<PaymentInstructions, ParseError> {
	const BTC_URI_PFX_LEN: usize = "bitcoin:".len();
	const LN_URI_PFX_LEN: usize = "lightning:".len();

	if instructions.len() >= BTC_URI_PFX_LEN
		&& instructions[..BTC_URI_PFX_LEN].eq_ignore_ascii_case("bitcoin:")
	{
		let (body, params) = split_once(&instructions[BTC_URI_PFX_LEN..], '?');
		let mut methods = Vec::new();
		let mut recipient_description = None;
		let mut pop_callback = None;
		if !body.is_empty() {
			let addr = Address::from_str(body).map_err(ParseError::InvalidOnChain)?;
			let address = addr.require_network(network).map_err(|_| ParseError::WrongNetwork)?;
			methods.push(PaymentMethod::OnChain { amount: None, address });
		}
		if let Some(params) = params {
			for param in params.split('&') {
				let (k, v) = split_once(param, '=');

				let mut parse_segwit = |pfx| {
					if let Some(address_string) = v {
						if address_string.len() < 3
							|| !address_string[..3].eq_ignore_ascii_case(pfx)
						{
							// `bc`/`tb` key-values must only include bech32/bech32m strings with
							// HRP "bc"/"tb" (i.e. mainnet/testnet Segwit addresses).
							let err = "BIP 321 bitcoin: URI contained a bc/tb instruction which was not a Segwit address (bc1*/tb1*)";
							return Err(ParseError::InvalidInstructions(err));
						}
						let addr = Address::from_str(address_string)
							.map_err(ParseError::InvalidOnChain)?;
						let address =
							addr.require_network(network).map_err(|_| ParseError::WrongNetwork)?;
						methods.push(PaymentMethod::OnChain { amount: None, address });
					} else {
						let err = "BIP 321 bitcoin: URI contained a bc (Segwit address) instruction without a value";
						return Err(ParseError::InvalidInstructions(err));
					}
					Ok(())
				};
				if k.eq_ignore_ascii_case("bc") || k.eq_ignore_ascii_case("req-bc") {
					parse_segwit("bc1")?;
				} else if k.eq_ignore_ascii_case("tb") || k.eq_ignore_ascii_case("req-tb") {
					parse_segwit("tb1")?;
				} else if k.eq_ignore_ascii_case("lightning")
					|| k.eq_ignore_ascii_case("req-lightning")
				{
					if let Some(invoice_string) = v {
						let invoice = Bolt11Invoice::from_str(invoice_string)
							.map_err(ParseError::InvalidBolt11)?;
						let (desc, method_iter) = instructions_from_bolt11(invoice, network)?;
						if let Some(desc) = desc {
							recipient_description = Some(desc);
						}
						for method in method_iter {
							methods.push(method);
						}
					} else {
						let err = "BIP 321 bitcoin: URI contained a lightning (BOLT 11 invoice) instruction without a value";
						return Err(ParseError::InvalidInstructions(err));
					}
				} else if k.eq_ignore_ascii_case("lno") || k.eq_ignore_ascii_case("req-lno") {
					if let Some(offer_string) = v {
						let offer =
							Offer::from_str(offer_string).map_err(ParseError::InvalidBolt12)?;
						if !offer.supports_chain(network.chain_hash()) {
							return Err(ParseError::WrongNetwork);
						}
						if let Some(expiry) = offer.absolute_expiry() {
							check_expiry(expiry)?;
						}
						if let Some(desc) = offer.description() {
							recipient_description = Some(desc.0.to_owned());
						}
						methods.push(PaymentMethod::LightningBolt12(offer));
					} else {
						let err = "BIP 321 bitcoin: URI contained a lightning (BOLT 11 invoice) instruction without a value";
						return Err(ParseError::InvalidInstructions(err));
					}
				} else if k.eq_ignore_ascii_case("amount") || k.eq_ignore_ascii_case("req-amount") {
					// We handle this in the second loop below
				} else if k.eq_ignore_ascii_case("label") || k.eq_ignore_ascii_case("req-label") {
					// We handle this in the second loop below
				} else if k.eq_ignore_ascii_case("message") || k.eq_ignore_ascii_case("req-message")
				{
					// We handle this in the second loop below
				} else if k.eq_ignore_ascii_case("pop") || k.eq_ignore_ascii_case("req-pop") {
					if k.eq_ignore_ascii_case("req-pop") && !supports_proof_of_payment_callbacks {
						return Err(ParseError::UnknownRequiredParameter);
					}
					if pop_callback.is_some() {
						let err = "Multiple proof of payment callbacks appeared in a BIP 321 bitcoin: URI";
						return Err(ParseError::InvalidInstructions(err));
					}
					if let Some(v) = v {
						let callback_uri = un_percent_encode(v)?;
						let (proto, _) = split_once(&callback_uri, ':');
						let proto_isnt_local_app = proto.eq_ignore_ascii_case("javascript")
							|| proto.eq_ignore_ascii_case("http")
							|| proto.eq_ignore_ascii_case("https")
							|| proto.eq_ignore_ascii_case("file")
							|| proto.eq_ignore_ascii_case("mailto")
							|| proto.eq_ignore_ascii_case("ftp")
							|| proto.eq_ignore_ascii_case("wss")
							|| proto.eq_ignore_ascii_case("ws")
							|| proto.eq_ignore_ascii_case("ssh")
							|| proto.eq_ignore_ascii_case("tel")
							|| proto.eq_ignore_ascii_case("data")
							|| proto.eq_ignore_ascii_case("blob");
						if proto_isnt_local_app {
							let err = "Proof of payment callback would not have opened a local app";
							return Err(ParseError::InvalidInstructions(err));
						}
						pop_callback = Some(callback_uri);
					} else {
						let err = "Missing value for a Proof of Payment instruction in a BIP 321 bitcoin: URI";
						return Err(ParseError::InvalidInstructions(err));
					}
				} else if k.len() >= 4 && k[..4].eq_ignore_ascii_case("req-") {
					return Err(ParseError::UnknownRequiredParameter);
				}
			}
			let mut amount = None;
			let mut label = None;
			let mut message = None;
			for param in params.split('&') {
				let (k, v) = split_once(param, '=');
				if k.eq_ignore_ascii_case("amount") || k.eq_ignore_ascii_case("req-amount") {
					if let Some(v) = v {
						if amount.is_some() {
							let err = "Multiple amount parameters in a BIP 321 bitcoin: URI";
							return Err(ParseError::InvalidInstructions(err));
						}
						let err = "The amount parameter in a BIP 321 bitcoin: URI was invalid";
						let btc_amt =
							bitcoin::Amount::from_str_in(v, bitcoin::Denomination::Bitcoin)
								.map_err(|_| ParseError::InvalidInstructions(err))?;
						amount = Some(Amount::from_sats(btc_amt.to_sat()));
					} else {
						let err = "Missing value for an amount parameter in a BIP 321 bitcoin: URI";
						return Err(ParseError::InvalidInstructions(err));
					}
				} else if k.eq_ignore_ascii_case("label") || k.eq_ignore_ascii_case("req-label") {
					if label.is_some() {
						let err = "Multiple label parameters in a BIP 321 bitcoin: URI";
						return Err(ParseError::InvalidInstructions(err));
					}
					label = v;
				} else if k.eq_ignore_ascii_case("message") || k.eq_ignore_ascii_case("req-message")
				{
					if message.is_some() {
						let err = "Multiple message parameters in a BIP 321 bitcoin: URI";
						return Err(ParseError::InvalidInstructions(err));
					}
					message = v;
				}
			}
			// Apply the amount parameter to all on-chain addresses
			if let Some(uri_amount) = amount {
				for method in methods.iter_mut() {
					if let PaymentMethod::OnChain { ref mut amount, .. } = method {
						*amount = Some(uri_amount);
					}
				}
			}

			if methods.is_empty() {
				return Err(ParseError::UnknownPaymentInstructions);
			}

			const MAX_MSATS: u64 = 21_000_000_0000_0000_000;
			let mut min_amt_msat = MAX_MSATS;
			let mut max_amt_msat = 0;
			let mut ln_amt_msat = None;
			let mut have_amountless_method = false;
			for method in methods.iter() {
				if let Some(amt_msat) = method.amount().map(|amt| amt.msats()) {
					if amt_msat > MAX_MSATS {
						let err = "Had a payment method in a BIP 321 bitcoin: URI which requested more than 21 million BTC";
						return Err(ParseError::InvalidInstructions(err));
					}
					if amt_msat < min_amt_msat {
						min_amt_msat = amt_msat;
					}
					if amt_msat > max_amt_msat {
						max_amt_msat = amt_msat;
					}
					match method {
						PaymentMethod::LightningBolt11(_) | PaymentMethod::LightningBolt12(_) => {
							if let Some(ln_amt_msat) = ln_amt_msat {
								if ln_amt_msat != amt_msat {
									let err = "Had multiple different amounts in lightning payment methods in a BIP 321 bitcoin: URI";
									return Err(ParseError::InconsistentInstructions(err));
								}
							}
							ln_amt_msat = Some(amt_msat);
						},
						PaymentMethod::OnChain { .. } => {},
					}
				} else {
					have_amountless_method = true;
				}
			}
			if (min_amt_msat != MAX_MSATS || max_amt_msat != 0) && have_amountless_method {
				let err = "Had some payment methods in a BIP 321 bitcoin: URI with required amounts, some without";
				return Err(ParseError::InconsistentInstructions(err));
			}
			if max_amt_msat.saturating_sub(min_amt_msat) > MAX_AMOUNT_DIFFERENCE.msats() {
				let err = "Payment methods differed in ";
				return Err(ParseError::InconsistentInstructions(err));
			}
		}
		if methods.is_empty() {
			Err(ParseError::UnknownPaymentInstructions)
		} else {
			Ok(PaymentInstructions { recipient_description, methods, pop_callback, hrn, hrn_proof })
		}
	} else if instructions.len() >= LN_URI_PFX_LEN
		&& instructions[..LN_URI_PFX_LEN].eq_ignore_ascii_case("lightning:")
	{
		// Though there is no specification, lightning: URIs generally only include BOLT 11
		// invoices.
		let invoice = Bolt11Invoice::from_str(&instructions[LN_URI_PFX_LEN..])
			.map_err(ParseError::InvalidBolt11)?;
		let (recipient_description, method_iter) = instructions_from_bolt11(invoice, network)?;
		Ok(PaymentInstructions {
			recipient_description,
			methods: method_iter.collect(),
			pop_callback: None,
			hrn,
			hrn_proof,
		})
	} else if let Ok(addr) = Address::from_str(instructions) {
		let address = addr.require_network(network).map_err(|_| ParseError::WrongNetwork)?;
		Ok(PaymentInstructions {
			recipient_description: None,
			methods: vec![PaymentMethod::OnChain { amount: None, address }],
			pop_callback: None,
			hrn,
			hrn_proof,
		})
	} else if let Ok(invoice) = Bolt11Invoice::from_str(instructions) {
		let (recipient_description, method_iter) = instructions_from_bolt11(invoice, network)?;
		Ok(PaymentInstructions {
			recipient_description,
			methods: method_iter.collect(),
			pop_callback: None,
			hrn,
			hrn_proof,
		})
	} else if let Ok(offer) = Offer::from_str(instructions) {
		if !offer.supports_chain(network.chain_hash()) {
			return Err(ParseError::WrongNetwork);
		}
		if let Some(expiry) = offer.absolute_expiry() {
			check_expiry(expiry)?;
		}
		Ok(PaymentInstructions {
			recipient_description: offer.description().map(|s| s.0.to_owned()),
			methods: vec![PaymentMethod::LightningBolt12(offer)],
			pop_callback: None,
			hrn,
			hrn_proof,
		})
	} else {
		Err(ParseError::UnknownPaymentInstructions)
	}
}

/// The resolution of a Human Readable Name
pub struct HrnResolution {
	/// A DNSSEC proof as used in BIP 353.
	///
	/// If the HRN was resolved using BIP 353, this should be set to a full proof which can later
	/// be copied to PSBTs for hardware wallet verification or stored as a part of proof of
	/// payment.
	pub proof: Option<Vec<u8>>,
	/// The result of the resolution.
	///
	/// This should contain a string which can be parsed as further payment instructions. For a BIP
	/// 353 resolution, this will contain a full BIP 321 bitcoin: URI, for a LN-Address resolution
	/// this will contain a lightning BOLT 11 invoice.
	pub result: String,
}

/// A future which resolves to a [`HrnResolution`].
pub type HrnResolutionFuture<'a> =
	Pin<Box<dyn Future<Output = Result<HrnResolution, &'static str>> + Send + 'a>>;

/// An arbitrary resolver for a Human Readable Name.
///
/// In general, such a resolver should first attempt to resolve using DNSSEC as defined in BIP 353.
///
/// For clients that also support LN-Address, if the BIP 353 resolution fails they should then fall
/// back to LN-Address to resolve to a Lightning BOLT 11 using HTTP.
///
/// A resolver which uses any (DNSSEC-enabled) recursive DNS resolver to resolve BIP 353 HRNs is
/// provided in
#[cfg_attr(feature = "std", doc = "[`dns_resolver::DNSHrnResolver`]")]
#[cfg_attr(not(feature = "std"), doc = "`dns_resolver::DNSHrnResolver`")]
/// if the crate is built with the `std` feature. Note that using this reveals who we are paying to
/// the recursive DNS resolver.
///
/// A resolver which uses HTTPS to `dns.google` and HTTPS to arbitrary servers for LN-Address is
/// provided in
#[cfg_attr(feature = "http", doc = "[`http_resolver::HTTPHrnResolver`]")]
#[cfg_attr(not(feature = "http"), doc = "`http_resolver::HTTPHrnResolver`")]
/// if this crate is built with the `http` feature. Note that using this generally reveals our IP
/// address to recipients,  as well as potentially who we are paying to Google.
pub trait HrnResolver {
	/// Resolves the given Human Readable Name into a [`HrnResolution`] containing a result which
	/// can be further parsed as payment instructions.
	fn resolve_hrn<'a>(&'a self, hrn: &'a HumanReadableName) -> HrnResolutionFuture<'a>;
}

/// An HRN "resolver" that never succeeds at resolving.
#[derive(Clone, Copy)]
pub struct DummyHrnResolver;

impl HrnResolver for DummyHrnResolver {
	fn resolve_hrn<'a>(&'a self, _hrn: &'a HumanReadableName) -> HrnResolutionFuture<'a> {
		Box::pin(async { Err("Human Readable Name resolution not supported") })
	}
}

impl PaymentInstructions {
	/// Resolves a string into [`PaymentInstructions`].
	pub async fn parse<H: HrnResolver>(
		instructions: &str, network: Network, hrn_resolver: H,
		supports_proof_of_payment_callbacks: bool,
	) -> Result<PaymentInstructions, ParseError> {
		let supports_pops = supports_proof_of_payment_callbacks;
		if let Ok(hrn) = HumanReadableName::from_encoded(instructions) {
			let resolution = hrn_resolver.resolve_hrn(&hrn).await;
			let resolution = resolution.map_err(ParseError::HrnResolutionError)?;
			let res = &resolution.result;
			parse_resolved_instructions(res, network, supports_pops, Some(hrn), resolution.proof)
		} else {
			parse_resolved_instructions(instructions, network, supports_pops, None, None)
		}
	}
}

#[cfg(test)]
mod tests {
	use alloc::format;
	use alloc::str::FromStr;
	use alloc::string::ToString;

	use super::*;

	const SAMPLE_INVOICE_WITH_FALLBACK: &str = "lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzq9qrsgqdfjcdk6w3ak5pca9hwfwfh63zrrz06wwfya0ydlzpgzxkn5xagsqz7x9j4jwe7yj7vaf2k9lqsdk45kts2fd0fkr28am0u4w95tt2nsq76cqw0";
	const SAMPLE_INVOICE: &str = "lnbc20m1pn7qa2ndqqnp4q0d3p2sfluzdx45tqcsh2pu5qc7lgq0xs578ngs6s0s68ua4h7cvspp5kwzshmne5zw3lnfqdk8cv26mg9ndjapqzhcxn2wtn9d6ew5e2jfqsp5h3u5f0l522vs488h6n8zm5ca2lkpva532fnl2kp4wnvsuq445erq9qyysgqcqpcxqppz4395v2sjh3t5pzckgeelk9qf0z3fm9jzxtjqpqygayt4xyy7tpjvq5pe7f6727du2mg3t2tfe0cd53de2027ff7es7smtew8xx5x2spwuvkdz";
	const SAMPLE_OFFER: &str = "lno1qgs0v8hw8d368q9yw7sx8tejk2aujlyll8cp7tzzyh5h8xyppqqqqqqgqvqcdgq2qenxzatrv46pvggrv64u366d5c0rr2xjc3fq6vw2hh6ce3f9p7z4v4ee0u7avfynjw9q";
	const SAMPLE_BIP21: &str = "bitcoin:1andreas3batLhQa2FawWjeyjCqyBzypd?amount=50&label=Luke-Jr&message=Donation%20for%20project%20xyz";

	const SAMPLE_BIP21_WITH_INVOICE: &str = "bitcoin:BC1QYLH3U67J673H6Y6ALV70M0PL2YZ53TZHVXGG7U?amount=0.00001&label=sbddesign%3A%20For%20lunch%20Tuesday&message=For%20lunch%20Tuesday&lightning=LNBC10U1P3PJ257PP5YZTKWJCZ5FTL5LAXKAV23ZMZEKAW37ZK6KMV80PK4XAEV5QHTZ7QDPDWD3XGER9WD5KWM36YPRX7U3QD36KUCMGYP282ETNV3SHJCQZPGXQYZ5VQSP5USYC4LK9CHSFP53KVCNVQ456GANH60D89REYKDNGSMTJ6YW3NHVQ9QYYSSQJCEWM5CJWZ4A6RFJX77C490YCED6PEMK0UPKXHY89CMM7SCT66K8GNEANWYKZGDRWRFJE69H9U5U0W57RRCSYSAS7GADWMZXC8C6T0SPJAZUP6";
	#[cfg(not(feature = "std"))]
	const SAMPLE_BIP21_WITH_INVOICE_ADDR: &str = "bc1qylh3u67j673h6y6alv70m0pl2yz53tzhvxgg7u";
	#[cfg(not(feature = "std"))]
	const SAMPLE_BIP21_WITH_INVOICE_INVOICE: &str = "lnbc10u1p3pj257pp5yztkwjcz5ftl5laxkav23zmzekaw37zk6kmv80pk4xaev5qhtz7qdpdwd3xger9wd5kwm36yprx7u3qd36kucmgyp282etnv3shjcqzpgxqyz5vqsp5usyc4lk9chsfp53kvcnvq456ganh60d89reykdngsmtj6yw3nhvq9qyyssqjcewm5cjwz4a6rfjx77c490yced6pemk0upkxhy89cmm7sct66k8gneanwykzgdrwrfje69h9u5u0w57rrcsysas7gadwmzxc8c6t0spjazup6";

	const SAMPLE_BIP21_WITH_INVOICE_AND_LABEL: &str = "bitcoin:tb1p0vztr8q25czuka5u4ta5pqu0h8dxkf72mam89cpg4tg40fm8wgmqp3gv99?amount=0.000001&label=yooo&lightning=lntbs1u1pjrww6fdq809hk7mcnp4qvwggxr0fsueyrcer4x075walsv93vqvn3vlg9etesx287x6ddy4xpp5a3drwdx2fmkkgmuenpvmynnl7uf09jmgvtlg86ckkvgn99ajqgtssp5gr3aghgjxlwshnqwqn39c2cz5hw4cnsnzxdjn7kywl40rru4mjdq9qyysgqcqpcxqrpwurzjqfgtsj42x8an5zujpxvfhp9ngwm7u5lu8lvzfucjhex4pq8ysj5q2qqqqyqqv9cqqsqqqqlgqqqqqqqqfqzgl9zq04nzpxyvdr8vj3h98gvnj3luanj2cxcra0q2th4xjsxmtj8k3582l67xq9ffz5586f3nm5ax58xaqjg6rjcj2vzvx2q39v9eqpn0wx54";

	#[tokio::test]
	async fn parse_address() {
		let addr_str = "1andreas3batLhQa2FawWjeyjCqyBzypd";
		let parsed =
			PaymentInstructions::parse(&addr_str, Network::Bitcoin, DummyHrnResolver, false)
				.await
				.unwrap();

		assert_eq!(parsed.methods.len(), 1);
		assert_eq!(parsed.methods[0].amount(), None);
		assert_eq!(parsed.recipient_description, None);
		if let PaymentMethod::OnChain { amount, address } = &parsed.methods[0] {
			assert_eq!(*amount, None);
			assert_eq!(*address, Address::from_str(addr_str).unwrap().assume_checked());
		} else {
			panic!("Wrong method");
		}
	}

	// Test a handful of ways a lightning invoice might be communicated
	async fn check_ln_invoice(inv: &str) -> Result<PaymentInstructions, ParseError> {
		assert!(inv.chars().all(|c| c.is_ascii_lowercase() || c.is_digit(10)), "{}", inv);
		let resolver = DummyHrnResolver;
		let raw = PaymentInstructions::parse(inv, Network::Bitcoin, resolver, false).await;

		let ln_uri = format!("lightning:{}", inv);
		let uri = PaymentInstructions::parse(&ln_uri, Network::Bitcoin, resolver, false).await;
		assert_eq!(raw, uri);

		let ln_uri = format!("LIGHTNING:{}", inv);
		let uri = PaymentInstructions::parse(&ln_uri, Network::Bitcoin, resolver, false).await;
		assert_eq!(raw, uri);

		let ln_uri = ln_uri.to_uppercase();
		let uri = PaymentInstructions::parse(&ln_uri, Network::Bitcoin, resolver, false).await;
		assert_eq!(raw, uri);

		let btc_uri = format!("bitcoin:?lightning={}", inv);
		let uri = PaymentInstructions::parse(&btc_uri, Network::Bitcoin, resolver, false).await;
		assert_eq!(raw, uri);

		let btc_uri = btc_uri.to_uppercase();
		let uri = PaymentInstructions::parse(&btc_uri, Network::Bitcoin, resolver, false).await;
		assert_eq!(raw, uri);

		let btc_uri = format!("bitcoin:?req-lightning={}", inv);
		let uri = PaymentInstructions::parse(&btc_uri, Network::Bitcoin, resolver, false).await;
		assert_eq!(raw, uri);

		let btc_uri = btc_uri.to_uppercase();
		let uri = PaymentInstructions::parse(&btc_uri, Network::Bitcoin, resolver, false).await;
		assert_eq!(raw, uri);

		raw
	}

	#[cfg(not(feature = "std"))]
	#[tokio::test]
	async fn parse_invoice() {
		let invoice = Bolt11Invoice::from_str(SAMPLE_INVOICE).unwrap();
		let parsed = check_ln_invoice(SAMPLE_INVOICE).await.unwrap();

		assert_eq!(parsed.methods.len(), 1);
		assert_eq!(
			parsed.methods[0].amount(),
			invoice.amount_milli_satoshis().map(Amount::from_milli_sats),
		);
		assert_eq!(parsed.recipient_description, Some(String::new()));
		assert!(matches!(parsed.methods[0].clone(), PaymentMethod::LightningBolt11(_)));
	}

	#[cfg(feature = "std")]
	#[tokio::test]
	async fn parse_invoice() {
		assert_eq!(check_ln_invoice(SAMPLE_INVOICE).await, Err(ParseError::InstructionsExpired));
	}

	#[cfg(not(feature = "std"))]
	#[tokio::test]
	async fn parse_invoice_with_fallback() {
		let invoice = Bolt11Invoice::from_str(SAMPLE_INVOICE_WITH_FALLBACK).unwrap();
		let parsed = check_ln_invoice(SAMPLE_INVOICE_WITH_FALLBACK).await.unwrap();

		assert_eq!(parsed.methods.len(), 2);
		assert_eq!(
			parsed.methods[0].amount(),
			invoice.amount_milli_satoshis().map(Amount::from_milli_sats),
		);
		assert_eq!(
			parsed.methods[1].amount(),
			invoice.amount_milli_satoshis().map(Amount::from_milli_sats),
		);

		assert_eq!(parsed.recipient_description, None); // no description for a description hash
		let is_bolt11 = |meth: &&PaymentMethod| matches!(meth, &&PaymentMethod::LightningBolt11(_));
		assert_eq!(parsed.methods.iter().filter(is_bolt11).count(), 1);
		let is_onchain = |meth: &&PaymentMethod| matches!(meth, &&PaymentMethod::OnChain { .. });
		assert_eq!(parsed.methods.iter().filter(is_onchain).count(), 1);
	}

	#[cfg(feature = "std")]
	#[tokio::test]
	async fn parse_invoice_with_fallback() {
		assert_eq!(
			check_ln_invoice(SAMPLE_INVOICE_WITH_FALLBACK).await,
			Err(ParseError::InstructionsExpired),
		);
	}

	// Test a handful of ways a lightning offer might be communicated
	async fn check_ln_offer(offer: &str) -> Result<PaymentInstructions, ParseError> {
		assert!(offer.chars().all(|c| c.is_ascii_lowercase() || c.is_digit(10)), "{}", offer);
		let resolver = DummyHrnResolver;
		let raw = PaymentInstructions::parse(offer, Network::Signet, resolver, false).await;

		let btc_uri = format!("bitcoin:?lno={}", offer);
		let uri = PaymentInstructions::parse(&btc_uri, Network::Signet, resolver, false).await;
		assert_eq!(raw, uri);

		let btc_uri = btc_uri.to_uppercase();
		let uri = PaymentInstructions::parse(&btc_uri, Network::Signet, resolver, false).await;
		assert_eq!(raw, uri);

		let btc_uri = format!("bitcoin:?req-lno={}", offer);
		let uri = PaymentInstructions::parse(&btc_uri, Network::Signet, resolver, false).await;
		assert_eq!(raw, uri);

		let btc_uri = btc_uri.to_uppercase();
		let uri = PaymentInstructions::parse(&btc_uri, Network::Signet, resolver, false).await;
		assert_eq!(raw, uri);

		raw
	}

	#[tokio::test]
	async fn parse_offer() {
		let offer = Offer::from_str(SAMPLE_OFFER).unwrap();
		let amt_msats = match offer.amount() {
			None => None,
			Some(offer::Amount::Bitcoin { amount_msats }) => Some(amount_msats),
			Some(offer::Amount::Currency { .. }) => panic!(),
		};
		let parsed = check_ln_offer(SAMPLE_OFFER).await.unwrap();

		assert_eq!(parsed.methods.len(), 1);
		assert_eq!(parsed.methods[0].amount(), amt_msats.map(Amount::from_milli_sats));
		assert_eq!(parsed.recipient_description, Some("faucet".to_string()));
		assert!(matches!(parsed.methods[0].clone(), PaymentMethod::LightningBolt12(_)));
	}

	#[tokio::test]
	async fn parse_bip_21() {
		let parsed =
			PaymentInstructions::parse(SAMPLE_BIP21, Network::Bitcoin, DummyHrnResolver, false)
				.await
				.unwrap();

		assert_eq!(parsed.methods.len(), 1);
		assert_eq!(parsed.methods[0].amount(), Some(Amount::from_sats(5_000_000_000)));
		assert_eq!(parsed.recipient_description, None);
		assert!(matches!(
			parsed.methods[0].clone(),
			PaymentMethod::OnChain { amount: Some(_), .. }
		));
	}

	#[cfg(not(feature = "std"))]
	#[tokio::test]
	async fn parse_bip_21_with_invoice() {
		let parsed = PaymentInstructions::parse(
			SAMPLE_BIP21_WITH_INVOICE,
			Network::Bitcoin,
			DummyHrnResolver,
			false,
		)
		.await
		.unwrap();

		assert_eq!(parsed.methods.len(), 2);
		assert_eq!(parsed.onchain_payment_amount(), Some(Amount::from_milli_sats(1_000_000)));
		assert_eq!(parsed.ln_payment_amount(), Some(Amount::from_milli_sats(1_000_000)));
		assert_eq!(parsed.methods[0].amount(), Some(Amount::from_milli_sats(1_000_000)));
		assert_eq!(parsed.recipient_description, Some("sbddesign: For lunch Tuesday".to_string()));
		if let PaymentMethod::OnChain { amount, address } = &parsed.methods[0] {
			assert_eq!(*amount, Some(Amount::from_milli_sats(1_000_000)));
			assert_eq!(address.to_string(), SAMPLE_BIP21_WITH_INVOICE_ADDR);
		} else {
			panic!("Missing on-chain (or order changed)");
		}
		if let PaymentMethod::LightningBolt11(inv) = &parsed.methods[1] {
			assert_eq!(inv.to_string(), SAMPLE_BIP21_WITH_INVOICE_INVOICE);
		} else {
			panic!("Missing invoice (or order changed)");
		}
	}

	#[cfg(feature = "std")]
	#[tokio::test]
	async fn parse_bip_21_with_invoice() {
		assert_eq!(
			PaymentInstructions::parse(
				SAMPLE_BIP21_WITH_INVOICE,
				Network::Bitcoin,
				DummyHrnResolver,
				false,
			)
			.await,
			Err(ParseError::InstructionsExpired),
		);
	}

	#[cfg(not(feature = "std"))]
	#[tokio::test]
	async fn parse_bip_21_with_invoice_with_label() {
		let parsed = PaymentInstructions::parse(
			SAMPLE_BIP21_WITH_INVOICE_AND_LABEL,
			Network::Signet,
			DummyHrnResolver,
			false,
		)
		.await
		.unwrap();

		assert_eq!(parsed.methods.len(), 2);
		assert_eq!(parsed.onchain_payment_amount(), Some(Amount::from_milli_sats(100_000)));
		assert_eq!(parsed.ln_payment_amount(), Some(Amount::from_milli_sats(100_000)));
		assert_eq!(parsed.methods[0].amount(), Some(Amount::from_milli_sats(100_000)));
		assert_eq!(parsed.recipient_description, Some("yooo".to_string()));
		assert!(matches!(
			parsed.methods[0].clone(),
			PaymentMethod::OnChain { amount: Some(_), .. }
		));
		assert!(matches!(parsed.methods[1].clone(), PaymentMethod::LightningBolt11(_)));
	}

	#[cfg(feature = "std")]
	#[tokio::test]
	async fn parse_bip_21_with_invoice_with_label() {
		assert_eq!(
			PaymentInstructions::parse(
				SAMPLE_BIP21_WITH_INVOICE_AND_LABEL,
				Network::Signet,
				DummyHrnResolver,
				false,
			)
			.await,
			Err(ParseError::InstructionsExpired),
		);
	}
}
