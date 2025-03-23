build-holder:
	cargo build --bin holder
run-holder:
	cargo run --bin holder

build-verifier:
	cargo build --bin verifier
run-verifier:
	cargo run --bin verifier

build:
	cargo build --bin holder --bin verifier

