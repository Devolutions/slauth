#!/bin/bash

# https://stackoverflow.com/a/246128/1775923
SOURCE=${BASH_SOURCE[0]}
while [ -L "$SOURCE" ]; do
  DIR=$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )
  SOURCE=$(readlink "$SOURCE")
  [[ $SOURCE != /* ]] && SOURCE=$DIR/$SOURCE
done
DIR=$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )

wasm-pack build --scope devolutions --out-dir ./dist/web --target web -- --no-default-features --features "webauthn"
sed -i 's/"@devolutions\/slauth"/"@devolutions\/slauth-web"/' ${DIR}/../../dist/web/package.json
