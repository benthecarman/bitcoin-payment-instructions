#!/bin/sh
set -e
set -x

RUSTC_MINOR_VERSION=$(rustc --version | awk '{ split($2,a,"."); print a[2] }')

# Starting with version 1.39.0, the `tokio` crate has an MSRV of rustc 1.70.0
[ "$RUSTC_MINOR_VERSION" -lt 70 ] && cargo update -p tokio --precise "1.38.1" --verbose
[ "$RUSTC_MINOR_VERSION" -lt 70 ] && cargo update -p tokio-util --precise "0.7.10" --verbose

RUSTFLAGS='-D warnings' cargo clippy -- \
	`# We use this for sat groupings` \
	-A clippy::inconsistent-digit-grouping \
	`# Some stuff we do sometimes when its reasonable` \
	-A clippy::result-unit-err \
	-A clippy::large-enum-variant \
	-A clippy::if-same-then-else \
	-A clippy::needless-lifetimes \
	`# This doesn't actually work sometimes` \
	-A clippy::option-as-ref-deref
