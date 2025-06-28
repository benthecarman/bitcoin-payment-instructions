// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use bitcoin::Network;

use bitcoin_payment_instructions::amount::Amount;
use bitcoin_payment_instructions::hrn_resolution::{
	DummyHrnResolver, HrnResolution, HrnResolutionFuture, HrnResolver, HumanReadableName,
	LNURLResolutionFuture,
};
use bitcoin_payment_instructions::PaymentInstructions;

use lightning_invoice::Bolt11Invoice;

use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Mutex;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

// Emulate Waker::noop until we fuzz on 1.85
const VTABLE: RawWakerVTable = RawWakerVTable::new(clone_fn, dummy_fn, dummy_fn, dummy_fn);

fn clone_fn(p: *const ()) -> RawWaker {
	RawWaker::new(p, &VTABLE)
}

fn dummy_fn(_: *const ()) {}

struct Resolver<'a>(Mutex<(Option<Result<HrnResolution, &'static str>>, Option<&'a [u8]>)>);

impl HrnResolver for Resolver<'_> {
	fn resolve_hrn<'a>(&'a self, _: &'a HumanReadableName) -> HrnResolutionFuture<'a> {
		Box::pin(async {
			let mut us = self.0.lock().unwrap();
			us.0.take().unwrap()
		})
	}

	fn resolve_lnurl<'a>(&'a self, _: &'a str) -> HrnResolutionFuture<'a> {
		Box::pin(async {
			let mut us = self.0.lock().unwrap();
			us.0.take().unwrap()
		})
	}

	fn resolve_lnurl_to_invoice<'a>(
		&'a self, _: String, _: Amount, _: [u8; 32],
	) -> LNURLResolutionFuture<'a> {
		Box::pin(async {
			let mut us = self.0.lock().unwrap();
			if let Ok(s) = std::str::from_utf8(us.1.take().unwrap()) {
				Bolt11Invoice::from_str(s).map_err(|_| "Failed to parse invoice")
			} else {
				Err("Invalid utf8 for invoice")
			}
		})
	}
}

#[inline]
pub fn do_test(mut data: &[u8]) {
	if data.len() < 2 {
		return;
	}

	let mut bolt11 = None;

	let resolution = if (data[0] & 0b1100_0000) == 0b1100_0000 {
		Err("HRN resolution failed in fuzzing")
	} else if (data[0] & 0b1100_0000) == 0b1000_0000 {
		let result_len = (((data[0] & 0b0011_1111) as usize) << 8) | (data[1] as usize);
		if data.len() <= result_len + 2 {
			return;
		}
		let result = if let Ok(s) = String::from_utf8(data[2..result_len + 2].to_vec()) {
			s
		} else {
			return;
		};

		data = &data[result_len + 2..];
		Ok(HrnResolution::DNSSEC { result, proof: Some(vec![8; 32]) })
	} else {
		if data.len() <= 16 + 2 {
			return;
		}
		let min = Amount::from_milli_sats(u64::from_le_bytes((&data[..8]).try_into().unwrap()));
		data = &data[8..];
		let max = Amount::from_milli_sats(u64::from_le_bytes((&data[..8]).try_into().unwrap()));
		data = &data[8..];

		let bolt11_len = ((data[0] as usize) << 8) | (data[1] as usize);
		if data.len() <= bolt11_len + 2 {
			return;
		}

		bolt11 = Some(&data[2..bolt11_len + 2]);
		data = &data[bolt11_len + 2..];

		let mut expected_description_hash = [0; 32];
		expected_description_hash[31] = 42;

		Ok(HrnResolution::LNURLPay {
			min_value: if let Ok(min) = min { min } else { return },
			max_value: if let Ok(max) = max { max } else { return },
			expected_description_hash,
			recipient_description: Some("Payment in fuzzing".to_owned()),
			callback: "https://callback.uri/in/fuzzing".to_owned(),
		})
	};

	let resolver = Resolver(Mutex::new((Some(resolution), bolt11)));

	if let Ok(s) = std::str::from_utf8(data) {
		let waker = unsafe { Waker::from_raw(clone_fn(std::ptr::null())) };

		let fut = PaymentInstructions::parse(s, Network::Bitcoin, &resolver, true);
		// With our resolver, all instructions should resolve on the first `poll`.
		let res = Future::poll(Pin::new(&mut Box::pin(fut)), &mut Context::from_waker(&waker));
		assert!(matches!(res, Poll::Ready(_)));

		let fut = PaymentInstructions::parse(s, Network::Bitcoin, &DummyHrnResolver, false);
		// With a DummyHrnResolver, all instructions should resolve on the first `poll`.
		let res = Future::poll(Pin::new(&mut Box::pin(fut)), &mut Context::from_waker(&waker));
		assert!(matches!(res, Poll::Ready(_)));
	}
}

pub fn parse_test(data: &[u8]) {
	do_test(data);
}

#[no_mangle]
pub extern "C" fn parse_run(data: *const u8, datalen: usize) {
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
