To build a binary:

1. Clone the wirefilter repo \
   `git clone https://github.com/cloudflare/wirefilter`
2. Checkout the commit from commit_hash file \
   `git checkout ${COMMIT}`
3. Apply the patches in order, \
   `git am ../firewalker/lib/*.patch`
4. Build a new release version of the artifact. \

```bash
# install cross for cross-compilation
cargo install cross --git https://github.com/cross-rs/cross

cross build --release --target aarch64-apple-darwin -p wirefilter-ffi
cross build --release --target x86_64-apple-darwin -p wirefilter-ffi
cross build --release --target x86_64-unknown-linux-gnu -p wirefilter-ffi

cp ./target/aarch64-apple-darwin/release/libwirefilter_ffi.dylib ../firewalker/lib/libwirefilter_ffi_aarch64.dylib
cp ./target/x86_64-apple-darwin/release/libwirefilter_ffi.dylib ../firewalker/lib/libwirefilter_ffi.dylib
cp ./target/x86_64-unknown-linux-gnu/release/libwirefilter_ffi.so ../firewalker/lib/libwirefilter_ffi.so
```
