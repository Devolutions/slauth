#!/bin/bash

cbindgen src/lib.rs -l c > slauth.h

cargo lipo --targets \
aarch64-apple-ios \
armv7-apple-ios \
armv7s-apple-ios \
x86_64-apple-ios \
i386-apple-ios --release