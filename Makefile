all-builds:
	cargo build
	cargo build --release
	# test for actual `no_std`-ness
	cargo build --target thumbv7em-none-eabi
	cargo build --target thumbv7em-none-eabi --release
