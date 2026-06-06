//! Bark / Arkade address parsing.
//!
//! This module supports both Bark policy addresses and Arkade addresses. Both use `ark`/`tark`
//! Bech32m HRPs, but their payloads are different:
//!  * Bark uses a Bech32m field-element version followed by an opaque policy payload.
//!  * Arkade encodes 65 bytes: version, server x-only public key, and VTXO tap key.

use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use bitcoin::bech32::primitives::decode::CheckedHrpstring;
use bitcoin::bech32::{self, Bech32m, ByteIterExt, Fe32, Fe32IterExt, Hrp};
use bitcoin::key::XOnlyPublicKey;
use bitcoin::Network;

const HRP_MAINNET: &str = "ark";
const HRP_TESTNET: &str = "tark";
const VERSION_ARKADE: Fe32 = Fe32::Q;
const VERSION_POLICY: Fe32 = Fe32::P;
const ARKADE_ADDRESS_LEN: usize = 65;
const DELIVERY_MAILBOX: u8 = 0x01;
const MAILBOX_DELIVERY_LEN: usize = 34;

pub(crate) enum ParsedAddress {
	Bark(BarkAddress),
	Arkade(ArkadeAddress),
}

pub(crate) fn parse_address(s: &str) -> Result<ParsedAddress, ParseAddressError> {
	let checked = CheckedHrpstring::new::<Bech32m>(s).map_err(|_| ParseAddressError::Bech32)?;
	let testnet = hrp_is_testnet(checked.hrp())?;
	let bytes: Vec<_> = checked.byte_iter().collect();

	if bytes.len() == ARKADE_ADDRESS_LEN {
		return Ok(ParsedAddress::Arkade(ArkadeAddress::from_parts(testnet, bytes)?));
	}

	let version = checked.witness_version().ok_or(ParseAddressError::Empty)?;
	match version {
		VERSION_POLICY => Ok(ParsedAddress::Bark(BarkAddress::from_checked(testnet, checked)?)),
		VERSION_ARKADE => Err(ParseAddressError::InvalidArkadeLength(bytes.len())),
		_ => Err(ParseAddressError::UnknownVersion),
	}
}

/// A Bark policy address.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BarkAddress {
	testnet: bool,
	payload: Vec<u8>,
}

impl BarkAddress {
	/// Whether this address uses Bark's test-network HRP (`tark`).
	pub fn is_testnet(&self) -> bool {
		self.testnet
	}

	/// The raw address payload after the Bark address version field.
	pub fn payload(&self) -> &[u8] {
		&self.payload
	}

	/// Requires that this address matches the given Bitcoin network.
	pub fn require_network(self, network: Network) -> Result<Self, NetworkValidationError> {
		if self.testnet == (network != Network::Bitcoin) {
			Ok(self)
		} else {
			Err(NetworkValidationError)
		}
	}

	fn from_checked(
		testnet: bool, mut checked: CheckedHrpstring<'_>,
	) -> Result<Self, ParseAddressError> {
		let version = checked.remove_witness_version().ok_or(ParseAddressError::Empty)?;
		if version != VERSION_POLICY {
			return Err(ParseAddressError::UnknownVersion);
		}

		let payload: Vec<_> = checked.byte_iter().collect();
		validate_bark_payload(&payload)?;
		Ok(BarkAddress { testnet, payload })
	}
}

impl FromStr for BarkAddress {
	type Err = ParseAddressError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match parse_address(s)? {
			ParsedAddress::Bark(addr) => Ok(addr),
			ParsedAddress::Arkade(_) => Err(ParseAddressError::WrongAddressType),
		}
	}
}

impl fmt::Display for BarkAddress {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let hrp = hrp_for_testnet(self.testnet)?;
		let chars = [VERSION_POLICY]
			.into_iter()
			.chain(self.payload.iter().copied().bytes_to_fes())
			.with_checksum::<Bech32m>(&hrp)
			.chars();
		for c in chars {
			let mut buf = [0; 4];
			f.write_str(c.encode_utf8(&mut buf))?;
		}
		Ok(())
	}
}

impl fmt::Debug for BarkAddress {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Display::fmt(self, f)
	}
}

/// An Arkade address.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArkadeAddress {
	testnet: bool,
	version: u8,
	server: XOnlyPublicKey,
	vtxo_tap_key: XOnlyPublicKey,
}

impl ArkadeAddress {
	/// Whether this address uses Arkade's test-network HRP (`tark`).
	pub fn is_testnet(&self) -> bool {
		self.testnet
	}

	/// The Arkade address version byte.
	pub fn version(&self) -> u8 {
		self.version
	}

	/// The Ark server x-only public key.
	pub fn server(&self) -> XOnlyPublicKey {
		self.server
	}

	/// The VTXO tap key.
	pub fn vtxo_tap_key(&self) -> XOnlyPublicKey {
		self.vtxo_tap_key
	}

	/// Requires that this address matches the given Bitcoin network.
	pub fn require_network(self, network: Network) -> Result<Self, NetworkValidationError> {
		if self.testnet == (network != Network::Bitcoin) {
			Ok(self)
		} else {
			Err(NetworkValidationError)
		}
	}

	fn from_parts(testnet: bool, bytes: Vec<u8>) -> Result<Self, ParseAddressError> {
		if bytes.len() != ARKADE_ADDRESS_LEN {
			return Err(ParseAddressError::InvalidArkadeLength(bytes.len()));
		}

		let version = bytes[0];
		let server =
			XOnlyPublicKey::from_slice(&bytes[1..33]).map_err(|_| ParseAddressError::Pubkey)?;
		let vtxo_tap_key =
			XOnlyPublicKey::from_slice(&bytes[33..65]).map_err(|_| ParseAddressError::Pubkey)?;

		Ok(ArkadeAddress { testnet, version, server, vtxo_tap_key })
	}
}

impl FromStr for ArkadeAddress {
	type Err = ParseAddressError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match parse_address(s)? {
			ParsedAddress::Arkade(addr) => Ok(addr),
			ParsedAddress::Bark(_) => Err(ParseAddressError::WrongAddressType),
		}
	}
}

impl fmt::Display for ArkadeAddress {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let mut bytes = [0u8; ARKADE_ADDRESS_LEN];
		bytes[0] = self.version;
		bytes[1..33].copy_from_slice(&self.server.serialize());
		bytes[33..65].copy_from_slice(&self.vtxo_tap_key.serialize());
		bech32::encode_to_fmt::<Bech32m, _>(f, hrp_for_testnet(self.testnet)?, &bytes)
			.map_err(|_| fmt::Error)
	}
}

impl fmt::Debug for ArkadeAddress {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Display::fmt(self, f)
	}
}

/// Error parsing a Bark / Arkade address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseAddressError {
	/// The address was not a valid Bech32m string.
	Bech32,
	/// The address HRP was not `ark` or `tark`.
	Hrp,
	/// The address had no version field.
	Empty,
	/// The address version was not supported.
	UnknownVersion,
	/// The address was valid but was not the requested Bark / Arkade address type.
	WrongAddressType,
	/// The Arkade address had an invalid byte length.
	InvalidArkadeLength(usize),
	/// An Arkade x-only public key was invalid.
	Pubkey,
	/// The address payload ended unexpectedly.
	Eof,
	/// The address payload was malformed.
	Invalid(&'static str),
}

impl fmt::Display for ParseAddressError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Bech32 => f.write_str("bech32m decoding error"),
			Self::Hrp => f.write_str("invalid Bark / Arkade address HRP"),
			Self::Empty => f.write_str("empty Bark / Arkade address"),
			Self::UnknownVersion => f.write_str("unknown Bark / Arkade address version"),
			Self::WrongAddressType => f.write_str("wrong Bark / Arkade address type"),
			Self::InvalidArkadeLength(len) => {
				write!(f, "invalid Arkade address length: expected 65 bytes, got {}", len)
			},
			Self::Pubkey => f.write_str("invalid Arkade x-only public key"),
			Self::Eof => f.write_str("unexpected end of Bark / Arkade address payload"),
			Self::Invalid(msg) => f.write_str(msg),
		}
	}
}

/// Error returned when an address does not match the requested network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkValidationError;

fn hrp_is_testnet(hrp: Hrp) -> Result<bool, ParseAddressError> {
	if hrp.as_str() == HRP_MAINNET {
		Ok(false)
	} else if hrp.as_str() == HRP_TESTNET {
		Ok(true)
	} else {
		Err(ParseAddressError::Hrp)
	}
}

fn hrp_for_testnet(testnet: bool) -> Result<Hrp, fmt::Error> {
	Hrp::parse(if testnet { HRP_TESTNET } else { HRP_MAINNET }).map_err(|_| fmt::Error)
}

fn validate_bark_payload(payload: &[u8]) -> Result<(), ParseAddressError> {
	let mut pos = 0;
	read_slice(payload, &mut pos, 4)?;

	let policy_len = read_compact_size(payload, &mut pos)?;
	if policy_len == 0 {
		return Err(ParseAddressError::Invalid("empty Bark VTXO policy"));
	}
	read_slice(payload, &mut pos, policy_len)?;

	while pos < payload.len() {
		let delivery_len = read_compact_size(payload, &mut pos)?;
		let delivery = read_slice(payload, &mut pos, delivery_len)?;
		if delivery.is_empty() {
			return Err(ParseAddressError::Invalid("empty Bark VTXO delivery mechanism"));
		}
		if delivery[0] == DELIVERY_MAILBOX && delivery.len() != MAILBOX_DELIVERY_LEN {
			return Err(ParseAddressError::Invalid("invalid Bark mailbox delivery mechanism"));
		}
	}

	Ok(())
}

fn read_slice<'a>(
	payload: &'a [u8], pos: &mut usize, len: usize,
) -> Result<&'a [u8], ParseAddressError> {
	let end = pos.checked_add(len).ok_or(ParseAddressError::Eof)?;
	if end > payload.len() {
		return Err(ParseAddressError::Eof);
	}
	let slice = &payload[*pos..end];
	*pos = end;
	Ok(slice)
}

fn read_compact_size(payload: &[u8], pos: &mut usize) -> Result<usize, ParseAddressError> {
	let first = *read_slice(payload, pos, 1)?.first().ok_or(ParseAddressError::Eof)?;
	let value = match first {
		0x00..=0xfc => first as u64,
		0xfd => {
			let bytes = read_slice(payload, pos, 2)?;
			u16::from_le_bytes([bytes[0], bytes[1]]) as u64
		},
		0xfe => {
			let bytes = read_slice(payload, pos, 4)?;
			u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64
		},
		0xff => {
			let bytes = read_slice(payload, pos, 8)?;
			u64::from_le_bytes([
				bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
			])
		},
	};
	usize::try_from(value)
		.map_err(|_| ParseAddressError::Invalid("Bark / Arkade payload too large"))
}

#[cfg(test)]
mod tests {
	use alloc::string::ToString;

	use super::*;

	const BARK_MAINNET: &str = "ark1pwh9vsmezqqpharv69q4z8m6x364d5m5prnmcalcalq9pdmzw0y7mpveck4pcfhezqypczkrrj3lkx5ue4qrf4jc7ztpt9htdttmh2judhqnu7aue8p0y9mqkr4cf5";
	const BARK_TESTNET: &str = "tark1pwh9vsmezqqpharv69q4z8m6x364d5m5prnmcalcalq9pdmzw0y7mpveck4pcfhezqypczkrrj3lkx5ue4qrf4jc7ztpt9htdttmh2judhqnu7aue8p0y9mq47jn9z";
	const ARKADE_TESTNET: &str = "tark1qqellv77udfmr20tun8dvju5vgudpf9vxe8jwhthrkn26fz96pawqfdy8nk05rsmrf8h94j26905e7n6sng8y059z8ykn2j5xcuw4xt846qj6x";

	#[test]
	fn parse_bark_address() {
		let address = BarkAddress::from_str(BARK_MAINNET).unwrap();
		assert!(!address.is_testnet());
		assert_eq!(address.to_string(), BARK_MAINNET);
		assert!(address.payload().len() > 4);
		assert!(address.clone().require_network(Network::Bitcoin).is_ok());
		assert!(address.require_network(Network::Signet).is_err());

		let parsed = parse_address(BARK_MAINNET).unwrap();
		assert!(matches!(parsed, ParsedAddress::Bark(_)));
	}

	#[test]
	fn parse_testnet_bark_address() {
		let address = BarkAddress::from_str(BARK_TESTNET).unwrap();
		assert!(address.is_testnet());
		assert_eq!(address.to_string(), BARK_TESTNET);
		assert!(address.clone().require_network(Network::Signet).is_ok());
		assert!(address.require_network(Network::Bitcoin).is_err());
	}

	#[test]
	fn parse_arkade_address() {
		let address = ArkadeAddress::from_str(ARKADE_TESTNET).unwrap();
		assert!(address.is_testnet());
		assert_eq!(address.to_string(), ARKADE_TESTNET);
		assert_eq!(address.version(), 0);
		assert_eq!(
			address.server().to_string(),
			"33ffb3dee353b1a9ebe4ced64b946238d0a4ac364f275d771da6ad2445d07ae0"
		);
		assert_eq!(
			address.vtxo_tap_key().to_string(),
			"25a43cecfa0e1b1a4f72d64ad15f4cfa7a84d0723e8511c969aa543638ea9967"
		);
		assert!(address.clone().require_network(Network::Regtest).is_ok());
		assert!(address.require_network(Network::Bitcoin).is_err());

		let parsed = parse_address(ARKADE_TESTNET).unwrap();
		assert!(matches!(parsed, ParsedAddress::Arkade(_)));
	}

	#[test]
	fn parse_mainnet_arkade_address() {
		let address = ArkadeAddress {
			testnet: false,
			version: 0,
			server: XOnlyPublicKey::from_str(
				"33ffb3dee353b1a9ebe4ced64b946238d0a4ac364f275d771da6ad2445d07ae0",
			)
			.unwrap(),
			vtxo_tap_key: XOnlyPublicKey::from_str(
				"25a43cecfa0e1b1a4f72d64ad15f4cfa7a84d0723e8511c969aa543638ea9967",
			)
			.unwrap(),
		};
		let encoded = address.to_string();
		assert!(encoded.starts_with("ark1"));

		let parsed = ArkadeAddress::from_str(&encoded).unwrap();
		assert!(!parsed.is_testnet());
		assert_eq!(parsed, address);
		assert_eq!(parsed.to_string(), encoded);
		assert!(parsed.clone().require_network(Network::Bitcoin).is_ok());
		assert!(parsed.require_network(Network::Signet).is_err());

		let parsed = parse_address(&encoded).unwrap();
		assert!(matches!(parsed, ParsedAddress::Arkade(_)));
	}

	#[test]
	fn rejects_wrong_address_type() {
		assert_eq!(
			BarkAddress::from_str(ARKADE_TESTNET).unwrap_err(),
			ParseAddressError::WrongAddressType
		);
		assert_eq!(
			ArkadeAddress::from_str(BARK_MAINNET).unwrap_err(),
			ParseAddressError::WrongAddressType
		);
	}
}
