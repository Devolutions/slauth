#!/bin/bash

export PATH=$NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin:$PATH
CC=aarch64-linux-android21-clang cargo build --target aarch64-linux-android --release
CC=x86_64-linux-android21-clang cargo build --target x86_64-linux-android --release
