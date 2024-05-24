#!/bin/bash
wasm-pack build --scope devolutions --out-dir ./dist/bundler --target bundler -- --no-default-features --features "webauthn"
