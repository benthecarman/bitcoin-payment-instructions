//! Because lightning uses "milli-satoshis" rather than satoshis for its native currency amount,
//! parsing payment instructions requires amounts with sub-satoshi precision.
//!
//! Thus, here, we define an [`Amount`] type similar to [`bitcoin::Amount`] but with sub-satoshi
//! precision.

use core::fmt;

/// An amount of Bitcoin
///
/// Sadly, because lightning uses "milli-satoshis" we cannot directly use rust-bitcon's `Amount`
/// type.
///
/// In general, when displaying amounts to the user, you should use [`Self::sats_rounding_up`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
// TODO: Move this into lightning-types
pub struct Amount(u64);

impl fmt::Debug for Amount {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
		write!(f, "{} milli-satoshis", self.0)
	}
}

impl Amount {
	/// The amount in milli-satoshis
	#[inline]
	pub const fn msats(&self) -> u64 {
		self.0
	}

	/// The amount in satoshis, if it is exactly a whole number of sats.
	#[inline]
	pub const fn sats(&self) -> Result<u64, ()> {
		if self.0 % 1000 == 0 {
			Ok(self.0 / 1000)
		} else {
			Err(())
		}
	}

	/// The amount in satoshis, rounding up to the next whole satoshi.
	#[inline]
	pub const fn sats_rounding_up(&self) -> u64 {
		(self.0 + 999) / 1000
	}

	/// Constructs a new [`Amount`] for the given number of milli-satoshis.
	#[inline]
	pub const fn from_milli_sats(msats: u64) -> Self {
		Amount(msats)
	}

	/// Constructs a new [`Amount`] for the given number of satoshis.
	#[inline]
	pub const fn from_sats(sats: u64) -> Self {
		Amount(sats * 1000)
	}

	/// Adds an [`Amount`] to this [`Amount`], saturating to avoid overflowing 21 million bitcoin.
	#[inline]
	pub fn saturating_add(self, rhs: Amount) -> Amount {
		match self.0.checked_add(rhs.0) {
			Some(amt) if amt <= 21_000_000_0000_0000_000 => Amount(amt),
			_ => Amount(21_000_000_0000_0000_000),
		}
	}

	/// Subtracts an [`Amount`] from this [`Amount`], saturating to avoid underflowing.
	#[inline]
	pub fn saturating_sub(self, rhs: Amount) -> Amount {
		Amount(self.0.saturating_sub(rhs.0))
	}


	/// Returns an object that implements [`core::fmt::Display`] which writes out the amount, in
	/// bitcoin, with a decimal point between the whole-bitcoin and partial-bitcoin amounts, with
	/// any milli-satoshis rounded up to the next whole satoshi.
	#[inline]
	pub fn btc_decimal_rounding_up_to_sats(self) -> FormattedAmount {
		FormattedAmount(self)
	}
}

#[derive(Clone, Copy)]
/// A simple type which wraps an [`Amount`] and formats it according to instructions when it was
/// generated.
pub struct FormattedAmount(Amount);

impl fmt::Display for FormattedAmount {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
		let total_sats = self.0.sats_rounding_up();
		let btc = total_sats / 1_0000_0000;
		let mut sats = total_sats % 1_0000_0000;
		write!(f, "{}", btc)?;
		if sats != 0 {
			let mut digits = 8;
			while sats % 10 == 0 {
				digits -= 1;
				sats /= 10;
			}
			write!(f, ".{:0digits$}", sats, digits = digits)?;
		}
		Ok(())
	}
}

#[cfg(test)]
mod test {
	use super::Amount;

	use alloc::string::ToString;

	#[test]
	#[rustfmt::skip]
	fn test_display() {
		assert_eq!(Amount::from_milli_sats(0).btc_decimal_rounding_up_to_sats().to_string(),     "0");
		assert_eq!(Amount::from_milli_sats(1).btc_decimal_rounding_up_to_sats().to_string(),     "0.00000001");
		assert_eq!(Amount::from_sats(1).btc_decimal_rounding_up_to_sats().to_string(),           "0.00000001");
		assert_eq!(Amount::from_sats(10).btc_decimal_rounding_up_to_sats().to_string(),          "0.0000001");
		assert_eq!(Amount::from_sats(15).btc_decimal_rounding_up_to_sats().to_string(),          "0.00000015");
		assert_eq!(Amount::from_sats(1_0000).btc_decimal_rounding_up_to_sats().to_string(),      "0.0001");
		assert_eq!(Amount::from_sats(1_2345).btc_decimal_rounding_up_to_sats().to_string(),      "0.00012345");
		assert_eq!(Amount::from_sats(1_2345_6789).btc_decimal_rounding_up_to_sats().to_string(), "1.23456789");
		assert_eq!(Amount::from_sats(1_0000_0000).btc_decimal_rounding_up_to_sats().to_string(), "1");
		assert_eq!(Amount::from_sats(5_0000_0000).btc_decimal_rounding_up_to_sats().to_string(), "5");
	}
}
