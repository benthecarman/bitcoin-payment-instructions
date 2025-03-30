// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use bitcoin::Network;

use bitcoin_payment_instructions::hrn_resolution::DummyHrnResolver;
use bitcoin_payment_instructions::PaymentInstructions;

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

// Emulate Waker::noop until we fuzz on 1.85
const VTABLE: RawWakerVTable = RawWakerVTable::new(clone_fn, dummy_fn, dummy_fn, dummy_fn);

fn clone_fn(p: *const ()) -> RawWaker {
	RawWaker::new(p, &VTABLE)
}

fn dummy_fn(_: *const ()) {}

#[inline]
pub fn do_test(data: &[u8]) {
	if let Ok(s) = std::str::from_utf8(data) {
		let waker = unsafe { Waker::from_raw(clone_fn(std::ptr::null())) };

		let fut = PaymentInstructions::parse(s, Network::Bitcoin, &DummyHrnResolver, true);
		// With a DummyHrnResolver, all instructions should resolve on the first `poll`.
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
