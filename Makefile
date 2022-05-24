all: style lint test-all
.PHONY: all

check: style lint
.PHONY: check

build:
	@cargo build --all-features
.PHONY: build

doc:
	@cargo doc
.PHONY: doc

test:
	@cargo test
.PHONY: test

test-all:
	@cargo test --all-features
.PHONY: test-all

style:
	@rustup component add rustfmt --toolchain stable 2> /dev/null
	cargo +stable fmt --all -- --check
.PHONY: style

format:
	@rustup component add rustfmt --toolchain stable 2> /dev/null
	@cargo +stable fmt --all
.PHONY: format

lint:
	@rustup component add clippy --toolchain stable 2> /dev/null
	@cargo +stable clippy --all-targets --all-features -- -D warnings
.PHONY: lint
