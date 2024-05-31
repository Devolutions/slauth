cargo lipo --release
mv target/universal/release/libslauth.a target/universal/release/libslauth_universal.a
mv target/x86_64-apple-ios/release/libslauth.a target/x86_64-apple-ios/release/libslauth_x86.a
mv target/aarch64-apple-ios/release/libslauth.a target/aarch64-apple-ios/release/libslauth_arm64.a