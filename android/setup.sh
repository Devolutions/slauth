#!/bin/bash

rustup target add \
x86_64-linux-android \
aarch64-linux-android \
armv7-linux-androideabi \
i686-linux-android \
arm-linux-androideabi

cargo install cbindgen
mkdir android/NDK

# arm
${NDK_HOME}/build/tools/make_standalone_toolchain.py --api 23 --arch arm64 --install-dir android/NDK/arm64
${NDK_HOME}/build/tools/make_standalone_toolchain.py --api 23 --arch arm --install-dir android/NDK/arm

# x86
${NDK_HOME}/build/tools/make_standalone_toolchain.py --api 23 --arch x86_64 --install-dir android/NDK/x86_64
${NDK_HOME}/build/tools/make_standalone_toolchain.py --api 23 --arch x86 --install-dir android/NDK/x86