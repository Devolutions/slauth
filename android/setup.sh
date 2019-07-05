#!/bin/bash

rustup target add \
x86_64-linux-android \
aarch64-linux-android \
armv7-linux-androideabi \
i686-linux-android \
arm-linux-androideabi

cargo install cbindgen