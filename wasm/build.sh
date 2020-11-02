#!/bin/bash
wasm-pack build --out-dir ./dist/bundler --target bundler
wasm-pack build --out-dir ./dist/node --target nodejs