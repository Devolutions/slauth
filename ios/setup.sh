#!/bin/bash

rustup target add \
aarch64-apple-ios \
armv7-apple-ios \
armv7s-apple-ios \
x86_64-apple-ios \
i386-apple-ios

cargo install cbindgen
cargo install cargo-lipo