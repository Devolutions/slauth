#!/bin/bash

cbindgen src/lib.rs -l c > slauth.h

cargo lipo --targets \
aarch64-apple-ios \
armv7-apple-ios \
armv7s-apple-ios \
x86_64-apple-ios \
i386-apple-ios --release

mkdir ./target/ios

cp ./target/aarch64-apple-ios/release/libslauth.a ./target/ios/libslauth_arm64.a
cp ./target/armv7-apple-ios/release/libslauth.a ./target/ios/libslauth_arm_v7.a
cp ./target/armv7s-apple-ios/release/libslauth.a ./target/ios/libslauth_arm_v7s.a
cp ./target/i386-apple-ios/release/libslauth.a ./target/ios/libslauth_i386.a
cp ./target/universal/release/libslauth.a ./target/ios/libslauth_universal.a
cp ./target/x86_64-apple-ios/release/libslauth.a ./target/ios/libslauth_x86.a