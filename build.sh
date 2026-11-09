#!/usr/bin/env bash
# Cross-compile release binaries for the supported Linux targets using
# cross (https://github.com/cross-rs/cross).
#
# Prerequisites:
#   * docker (or podman) running
#   * cross installed (https://crates.io/crates/cross)
#   * stable toolchain via rustup (all targets except mipsel)
#   * nightly toolchain via rustup for mipsel (build-std needs it, since
#     the Rust toolchain ships no prebuilt std for mipsel-unknown-linux-musl)
#
# Output: statically linked binaries in ./dist/
#
# Usage: ./build.sh [target-name-for-this-host]

set -euo pipefail

DIST="${DIST:-dist}"

# Target triples to build (each must have an entry in Cross.toml).
TARGETS=(
    x86_64-unknown-linux-musl
    aarch64-unknown-linux-musl
    mipsel-unknown-linux-musl
)

mkdir -p "$DIST"

for target in "${TARGETS[@]}"; do
    if [ "$target" = "mipsel-unknown-linux-musl" ]; then
        # Tier-3 target: no prebuilt std, must be built from source.
        cross +nightly build --release -Z build-std=std,core,alloc --target "$target"
    else
        cross build --release --target "$target"
    fi
    binary="target/$target/release/wgmon"
    out="$DIST/wgmon-${target}${EXE_EXT:-}"
    cp "$binary" "$out"
    echo "built: $out"
done

echo "ok: artifacts are in ./$DIST/"
