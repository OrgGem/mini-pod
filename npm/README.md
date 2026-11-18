# mini-pod on npm

After an npm release is available, install the CLI and daemon with Node.js 18 or later:

```sh
npm install -g @orggem/mini-pod
sandbox-cli --help
sandboxd --help
```

Prebuilt binaries are provided for Windows x64, Linux x64/arm64 (glibc), and macOS x64/arm64. Alpine Linux and other musl-based systems are not supported by these binaries. Do not omit optional dependencies when installing the package.

The npm package does not include QEMU or a signed guest runtime bundle. Install or supply those separately, start `sandboxd serve` with a trusted bundle and public key, then connect with `sandbox-cli`. See the [mini-pod README](https://github.com/OrgGem/mini-pod#readme) for configuration and examples.
