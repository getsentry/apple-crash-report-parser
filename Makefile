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
	cargo +stable fmt -- --check
.PHONY: style

format:
	@rustup component add rustfmt --toolchain stable 2> /dev/null
	@cargo +stable fmt
.PHONY: format

lint:
	@rustup component add clippy --toolchain stable 2> /dev/null
	@cargo +stable clippy  --all-features --tests -- -D clippy::all
.PHONY: lint
