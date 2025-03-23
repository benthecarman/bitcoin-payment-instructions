#!/bin/bash
set -eox pipefail

RUSTC_MINOR_VERSION=$(rustc --version | awk '{ split($2,a,"."); print a[2] }')

# Starting with version 1.39.0, the `tokio` crate has an MSRV of rustc 1.70.0
[ "$RUSTC_MINOR_VERSION" -lt 70 ] && cargo update -p tokio --precise "1.38.1" --verbose
[ "$RUSTC_MINOR_VERSION" -lt 70 ] && cargo update -p tokio-util --precise "0.7.10" --verbose

export RUST_BACKTRACE=1

cargo check --verbose --color always
cargo check --release --verbose --color always
cargo test
[ "$RUSTC_MINOR_VERSION" -gt 81 ] && cargo test --features http
cargo test --features std
[ "$RUSTC_MINOR_VERSION" -gt 81 ] && cargo doc --document-private-items --no-default-features
[ "$RUSTC_MINOR_VERSION" -gt 81 ] && cargo doc --document-private-items --features http,std
exit 0
