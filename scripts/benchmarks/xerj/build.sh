#!/bin/sh
set -eu
umask 022
# Generic x86-64 matches mini-pod's default TCG CPU; upstream defaults to v2.
export RUSTFLAGS='-C target-cpu=x86-64 -C target-feature=+crt-static'
export CARGO_TARGET_DIR=/build/target
export CARGO_HOME=/build/cargo
export CARGO_BUILD_JOBS=6
export CARGO_PROFILE_RELEASE_LTO=thin
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16
mkdir -p /out
rustc -Vv > /out/rustc.txt
apk info -v > /out/build-packages.txt
df -h /build
cargo build --locked --release --target x86_64-unknown-linux-musl --no-default-features --package xerj-server --bin xerj
cp /build/target/x86_64-unknown-linux-musl/release/xerj /out/xerj
file /out/xerj > /out/binary-format.txt
if readelf -l /out/xerj | grep -q INTERP; then
    echo 'Xerj must be a static musl executable for this guest' >&2
    exit 1
fi
sha256sum /out/xerj > /out/xerj.sha256
/out/xerj --version > /out/xerj-version.txt
