[![npm version](https://badge.fury.io/js/firewalker.svg)](https://www.npmjs.com/package/@tamkelvin313/firewalker)

The clone of [SerCeMan/firewalker](https://github.com/SerCeMan/firewalker), with adding apple silicon support. For the document please reference the orginal repo.

# Apple Silcon (M1) support issue for npm plugin `firewalker`

The npm package `firewalker` depends on binary build of [`wirefilter`](https://github.com/cloudflare/wirefilter) to run and execute the firewall rules to perform js based unit test. However,the binary build inside the npm package is `x86` based, not support with apple silcon machine, bring some troublesome during development.

The following is the guideline to resolve the problem and this plugin is only the clone with below modification

- Clone the following repo `https://github.com/cloudflare/wirefilter` with commit [2334ab150](https://github.com/cloudflare/wirefilter/commit/2334ab150abd803a555b1541a7e44891b7f5cc60).
- Apply the patch file at npm package [`SerCeMan/firewalker/blob/master/lib/wirefilter.patch`](https://github.com/SerCeMan/firewalker/blob/master/lib/wirefilter.patch)
- Build the `wirefilter` with `aarch64-apple-darwin` architecture. 
```
cargo build --release --target aarch64-apple-darwin
```
- Copy the birary file compiled at last step `wirefilter/target/aarch64-apple-darwin/release/libwirefilter_ffi.dylib` to replace the `node_modules/firewalker/lib/libwirefilter_ffi.dylib`