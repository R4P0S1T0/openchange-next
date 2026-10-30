#!/bin/sh
# Empty the vendored crates that are never compiled on Linux (Windows/WASI
# targets and tokio's cfg(tokio_taskdump) backtrace stack), as distributions do.
# Run from the top source directory after `cargo vendor --versioned-dirs vendor`.
set -eu

for dir in vendor/windows* vendor/wasi-* vendor/backtrace-* vendor/addr2line-* \
           vendor/gimli-* vendor/object-* vendor/miniz_oxide-* vendor/adler2-* \
           vendor/rustc-demangle-*; do
	test -f "$dir/Cargo.toml" || continue
	find "$dir" -mindepth 1 -maxdepth 1 ! -name Cargo.toml ! -name .cargo-checksum.json \
		! -name 'LICENSE*' ! -name 'license*' -exec rm -rf {} +
	# Cargo still parses these manifests, so keep the targets they name.
	mkdir -p "$dir/src"
	: > "$dir/src/lib.rs"
	if grep -q '^build = "build.rs"' "$dir/Cargo.toml"; then
		echo 'fn main() {}' > "$dir/build.rs"
	fi
	sed -i 's/^{"files":{.*},"package"/{"files":{},"package"/' "$dir/.cargo-checksum.json"
done
