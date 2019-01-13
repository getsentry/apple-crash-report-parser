all: test
.PHONY: all

clean:
	@cargo clean
.PHONY: clean

build:
	@cargo build
.PHONY: build

doc:
	@cargo doc --all-features
.PHONY: doc

test:
	@cargo test
	@cargo test --all-features
.PHONY: test

format-check:
	@rustup component add rustfmt 2> /dev/null
	@cargo fmt -- --check
.PHONY: format-check

lint:
	@rustup component add clippy 2> /dev/null
	@cargo clippy
.PHONY: lint
