#!/bin/bash

cbindgen src/lib.rs -l c > slauth.h

export PATH=$NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin:$PATH
CC=aarch64-linux-android21-clang cargo build --target aarch64-linux-android --release --features="android"
CC=armv7a-linux-androideabi21-clang cargo build --target armv7-linux-androideabi --release --features="android"
CC=i686-linux-android21-clang cargo build --target i686-linux-android --release --features="android"
CC=x86_64-linux-android21-clang cargo build --target x86_64-linux-android --release --features="android"
