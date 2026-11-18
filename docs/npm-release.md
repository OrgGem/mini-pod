# npm release procedure

The npm distribution contains `sandbox-cli` and `sandboxd`. QEMU and the signed guest runtime bundle are installed separately. The build produces a main package and five optional platform packages:

| npm package | Rust target |
| --- | --- |
| `@orggem/mini-pod-win32-x64` | `x86_64-pc-windows-msvc` |
| `@orggem/mini-pod-linux-x64` | `x86_64-unknown-linux-gnu` |
| `@orggem/mini-pod-linux-arm64` | `aarch64-unknown-linux-gnu` |
| `@orggem/mini-pod-darwin-x64` | `x86_64-apple-darwin` |
| `@orggem/mini-pod-darwin-arm64` | `aarch64-apple-darwin` |

Linux binaries require glibc and may require a sufficiently recent distribution; musl/Alpine is not supported. Windows ARM64 is out of scope. The supported platform list describes build targets, not independently verified runtime compatibility.

## Prepare the first release

1. Confirm that the publisher controls the npm `@orggem` scope and all six package names, or change the scope consistently in the package manifest and launcher before publishing. GitHub and npm organizations are separate.
2. Match `npm/package.json`'s version with `workspace.package.version` in `Cargo.toml`. The workflow checks that they match. Prerelease tags such as `v0.1.0-rc.1` are accepted for `0.1.0`; the tag sets the exact npm version.
3. Run the existing **Release Binaries** workflow manually with a unique prerelease `version`, for example `v0.1.0-bootstrap.1`. Download the `npm-main` and all five `npm-platform-*` workflow artifacts, each containing an npm tarball. A manual run defaults to `<workspace version>-dev` if no version is given.
4. If the packages do not exist yet, bootstrap them using an npm account authorized for the scope. From the directory containing the downloaded tarballs, publish every platform tarball first, then the main tarball, for example:

   ```sh
   npm login
   npm publish ./orggem-mini-pod-win32-x64-0.1.0-bootstrap.1.tgz --access public --tag next
   # Repeat for the four other platform tarballs, then:
   npm publish ./orggem-mini-pod-0.1.0-bootstrap.1.tgz --access public --tag next
   ```

   Each npm version is immutable; use a new prerelease version if republishing is needed. Do not publish the main package until all five matching platform packages are available.
5. In the npm settings for **each** of the six packages, configure GitHub Actions as a trusted publisher: GitHub owner `OrgGem`, repository `mini-pod`, workflow filename `release.yml`, and permission for direct `npm publish`. Follow [npm's trusted publishing instructions](https://docs.npmjs.com/trusted-publishers/); new connections expire if their first publish is not completed within npm's stated validation window.
6. In the GitHub repository's Actions variables, set `NPM_PUBLISH_ENABLED` to `true`. This explicitly enables publishing on future `v*` tag runs; manual runs only build artifacts. No npm token is needed by the workflow.

## Publish subsequent releases

Update the workspace and npm manifest versions together, then push the matching version tag. The release workflow builds all targets, uploads npm artifacts, publishes platform packages first, then the main package. Stable versions use npm's `latest` dist-tag; prereleases use `next`.

If publishing stops partway, some package versions may already exist while the main package was not published. Inspect npm and the artifacts before recovery; an existing version cannot be overwritten. Publish only the missing, matching tarballs with appropriate authorization, or release a new version. Never publish the main package without all five matching platform packages.

To verify an already published version, install it in a clean environment for each supported platform and run `sandbox-cli --help` and `sandboxd --help`; a complete sandbox also requires separately installed QEMU and a verified guest bundle.
