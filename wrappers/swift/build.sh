#!/bin/bash
set -e

# Build Rust libraries for iOS targets
cargo build --target aarch64-apple-ios --release
cargo build --target aarch64-apple-ios-sim --release
cargo build --target aarch64-apple-darwin --release
cargo build --target x86_64-apple-darwin --release

lipo target/x86_64-apple-darwin/release/libslauth.a target/aarch64-apple-darwin/release/libslauth.a -create -output target/libslauth.a

mkdir package
mkdir ./package/headers
cp slauth.h ./package/headers 

# Create XCFramework
xcodebuild -create-xcframework \
    -library target/aarch64-apple-ios/release/libslauth.a -headers ./package/headers \
    -library target/aarch64-apple-ios-sim/release/libslauth.a -headers ./package/headers \
    -library target/libslauth.a -headers ./package/headers \
    -output ./package/libslauth.xcframework

cp wrappers/swift/Package.swift ./package
cp -R wrappers/swift/classes ./package
cp -R wrappers/swift/ffi ./package

