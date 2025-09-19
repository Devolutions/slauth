#!/bin/bash

CURRENT_FOLDER=$(basename "$PWD")
if [ $CURRENT_FOLDER != "slauth" ];
then
    echo "Please run this script from the root of the project"
    exit 1
fi

export RUSTFLAGS="-C link-arg=-Wl,-z,max-page-size=16384 -C link-arg=-Wl,-z,common-page-size=16384"
export PATH=$NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin:$PATH
CC=aarch64-linux-android21-clang cargo build --target aarch64-linux-android --release --features "android"
CC=x86_64-linux-android21-clang cargo build --target x86_64-linux-android --release --features "android"

cp target/aarch64-linux-android/release/libslauth.so wrappers/android/src/main/jniLibs/arm64-v8a/libslauth.so
cp target/x86_64-linux-android/release/libslauth.so wrappers/android/src/main/jniLibs/x86_64/libslauth.so