#!/bin/bash

export PATH=$NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin:$PATH
CC=aarch64-linux-android21-clang cargo build --target aarch64-linux-android --release
CC=x86_64-linux-android21-clang cargo build --target x86_64-linux-android --release

cp ../../target/aarch64-linux-android/release/libslauth.so src/main/jniLibs/arm64-v8a/libslauth.so
cp ../../target/x86_64-linux-android/release/libslauth.so src/main/jniLibs/x86_64/libslauth.so