//! A type for storing Human Readable Names (HRNs) which can be resolved using BIP 353 and the DNS
//! or LNURL-Pay and LN-Address.

use alloc::string::{String, ToString};

/// A struct containing the two parts of a BIP 353 Human Readable Name - the user and domain parts.
///
/// The `user` and `domain` parts, together, cannot exceed 232 bytes in length, and both must be
/// non-empty.
///
/// To protect against [Homograph Attacks], both parts of a Human Readable Name must be plain
/// ASCII.
///
/// This struct can also be used for LN-Address recipients.
///
/// [Homograph Attacks]: https://en.wikipedia.org/wiki/IDN_homograph_attack
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct HumanReadableName {
	// TODO Remove the heap allocations given the whole data can't be more than 256 bytes.
	user: String,
	domain: String,
}

/// Check if the chars in `s` are allowed to be included in a hostname.
pub(crate) fn str_chars_allowed(s: &str) -> bool {
	s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

impl HumanReadableName {
	/// Constructs a new [`HumanReadableName`] from the `user` and `domain` parts. See the
	/// struct-level documentation for more on the requirements on each.
	pub fn new(user: String, mut domain: String) -> Result<HumanReadableName, ()> {
		// First normalize domain and remove the optional trailing `.`
		if domain.ends_with(".") {
			domain.pop();
		}
		// Note that `REQUIRED_EXTRA_LEN` includes the (now implicit) trailing `.`
		const REQUIRED_EXTRA_LEN: usize = ".user._bitcoin-payment.".len() + 1;
		if user.len() + domain.len() + REQUIRED_EXTRA_LEN > 255 {
			return Err(());
		}
		if user.is_empty() || domain.is_empty() {
			return Err(());
		}
		if !str_chars_allowed(&user) || !str_chars_allowed(&domain) {
			return Err(());
		}
		Ok(HumanReadableName { user, domain })
	}

	/// Constructs a new [`HumanReadableName`] from the standard encoding - `user`@`domain`.
	///
	/// If `user` includes the standard BIP 353 ₿ prefix it is automatically removed as required by
	/// BIP 353.
	pub fn from_encoded(encoded: &str) -> Result<HumanReadableName, ()> {
		if let Some((user, domain)) = encoded.strip_prefix('₿').unwrap_or(encoded).split_once("@")
		{
			Self::new(user.to_string(), domain.to_string())
		} else {
			Err(())
		}
	}

	/// Gets the `user` part of this Human Readable Name
	pub fn user(&self) -> &str {
		&self.user
	}

	/// Gets the `domain` part of this Human Readable Name
	pub fn domain(&self) -> &str {
		&self.domain
	}
}
