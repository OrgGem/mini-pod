#!/bin/sh
set -eu
rustc --edition=2021 --target x86_64-unknown-linux-musl -C target-cpu=x86-64 -C target-feature=+crt-static --test /harness/guest.rs -o /out/guest-tests
/out/guest-tests
rustc --edition=2021 --target x86_64-unknown-linux-musl -C target-cpu=x86-64 -C target-feature=+crt-static -C opt-level=3 -C strip=symbols /harness/guest.rs -o /out/guest-bench
sha256sum /out/guest-bench
