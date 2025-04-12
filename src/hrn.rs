//! A type for storing Human Readable Names (HRNs) which can be resolved using BIP 353 and the DNS
//! or LNURL-Pay and LN-Address.

// Note that `REQUIRED_EXTRA_LEN` includes the (implicit) trailing `.`
const REQUIRED_EXTRA_LEN: usize = ".user._bitcoin-payment.".len() + 1;

/// A struct containing the two parts of a BIP 353 Human Readable Name - the user and domain parts.
///
/// The `user` and `domain` parts, together, cannot exceed 231 bytes in length, and both must be
/// non-empty.
///
/// If you intend to handle non-ASCII `user` or `domain` parts, you must handle [Homograph Attacks]
/// and do punycode en-/de-coding yourself. This struc will always handle only plain ASCII `user`
/// and `domain` parts.
///
/// This struct can also be used for LN-Address recipients.
///
/// [Homograph Attacks]: https://en.wikipedia.org/wiki/IDN_homograph_attack
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct HumanReadableName {
	contents: [u8; 255 - REQUIRED_EXTRA_LEN],
	user_len: u8,
	domain_len: u8,
}

/// Check if the chars in `s` are allowed to be included in a hostname.
pub(crate) fn str_chars_allowed(s: &str) -> bool {
	s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

impl HumanReadableName {
	/// Constructs a new [`HumanReadableName`] from the `user` and `domain` parts. See the
	/// struct-level documentation for more on the requirements on each.
	pub fn new(user: &str, mut domain: &str) -> Result<HumanReadableName, ()> {
		// First normalize domain and remove the optional trailing `.`
		if domain.ends_with('.') {
			domain = &domain[..domain.len() - 1];
		}
		if user.len() + domain.len() + REQUIRED_EXTRA_LEN > 255 {
			return Err(());
		}
		if user.is_empty() || domain.is_empty() {
			return Err(());
		}
		if !str_chars_allowed(&user) || !str_chars_allowed(&domain) {
			return Err(());
		}
		let mut contents = [0; 255 - REQUIRED_EXTRA_LEN];
		contents[..user.len()].copy_from_slice(user.as_bytes());
		contents[user.len()..user.len() + domain.len()].copy_from_slice(domain.as_bytes());
		Ok(HumanReadableName {
			contents,
			user_len: user.len() as u8,
			domain_len: domain.len() as u8,
		})
	}

	/// Constructs a new [`HumanReadableName`] from the standard encoding - `user`@`domain`.
	///
	/// If `user` includes the standard BIP 353 ₿ prefix it is automatically removed as required by
	/// BIP 353.
	pub fn from_encoded(encoded: &str) -> Result<HumanReadableName, ()> {
		if let Some((user, domain)) = encoded.strip_prefix('₿').unwrap_or(encoded).split_once("@")
		{
			Self::new(user, domain)
		} else {
			Err(())
		}
	}

	/// Gets the `user` part of this Human Readable Name
	pub fn user(&self) -> &str {
		let bytes = &self.contents[..self.user_len as usize];
		core::str::from_utf8(bytes).expect("Checked in constructor")
	}

	/// Gets the `domain` part of this Human Readable Name
	pub fn domain(&self) -> &str {
		let user_len = self.user_len as usize;
		let bytes = &self.contents[user_len..user_len + self.domain_len as usize];
		core::str::from_utf8(bytes).expect("Checked in constructor")
	}
}
