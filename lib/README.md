To build a binary:
1. Clone the wirefilter repo \
   `git clone https://github.com/cloudflare/wirefilter`
2. Checkout the commit from commit_hash file \
   `git checkout ${COMMIT}`
3. Apply the patch, \
   `git apply wirefilter.patch`
4. Build a new release version of the artifact. \
   `cargo build --release --target -p wirefilter-ffi` \
   To build the apple silicon version, \
   `cargo build --release --target aarch64-apple-darwin -p wirefilter-ffi`
    