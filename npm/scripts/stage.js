'use strict';

const fs = require('node:fs');
const path = require('node:path');
const source = require('../package.json');

const targets = {
  'x86_64-pc-windows-msvc': ['win32', 'x64'],
  'x86_64-unknown-linux-gnu': ['linux', 'x64'],
  'aarch64-unknown-linux-gnu': ['linux', 'arm64'],
  'x86_64-apple-darwin': ['darwin', 'x64'],
  'aarch64-apple-darwin': ['darwin', 'arm64'],
};

function stage(kind, version, destination, binaries) {
  const semver = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*)?$/;
  if (!version || !semver.test(version) ||
      (version !== source.version && !version.startsWith(`${source.version}-`))) {
    throw new Error(`Expected version ${source.version} or a prerelease of it; got ${version}`);
  }

  if (kind !== 'main' && (!targets[kind] || !binaries)) {
    throw new Error(`Unsupported target or missing binary directory: ${kind}`);
  }
  fs.mkdirSync(destination);
  if (kind === 'main') {
    const manifest = {
      ...source,
      version,
      optionalDependencies: Object.fromEntries(
        Object.keys(source.optionalDependencies).map(name => [name, version]),
      ),
    };
    fs.writeFileSync(path.join(destination, 'package.json'), `${JSON.stringify(manifest, null, 2)}\n`);
    fs.cpSync(path.join(__dirname, '..', 'bin'), path.join(destination, 'bin'), { recursive: true });
    fs.copyFileSync(path.join(__dirname, '..', 'launcher.js'), path.join(destination, 'launcher.js'));
    fs.copyFileSync(path.join(__dirname, '..', 'README.md'), path.join(destination, 'README.md'));
    return;
  }

  const target = targets[kind];
  const [platform, arch] = target;
  const name = `${source.name}-${platform}-${arch}`;
  if (!(name in source.optionalDependencies)) throw new Error(`Missing dependency: ${name}`);
  const manifest = {
    name,
    version,
    description: `mini-pod binaries for ${platform} ${arch}`,
    license: source.license,
    repository: source.repository,
    os: [platform],
    cpu: [arch],
    ...(platform === 'linux' ? { libc: ['glibc'] } : {}),
    files: ['bin'],
    publishConfig: source.publishConfig,
  };
  fs.writeFileSync(path.join(destination, 'package.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  fs.mkdirSync(path.join(destination, 'bin'));
  for (const command of ['sandbox-cli', 'sandboxd']) {
    const filename = command + (platform === 'win32' ? '.exe' : '');
    const output = path.join(destination, 'bin', filename);
    fs.copyFileSync(path.join(binaries, filename), output);
    fs.chmodSync(output, 0o755);
  }
}

if (require.main === module) {
  try {
    const [kind, version, destination, binaries] = process.argv.slice(2);
    if (!kind || !version || !destination) {
      throw new Error('Usage: node npm/scripts/stage.js <main|rust-target> <version> <new-directory> [binary-directory]');
    }
    stage(kind, version, destination, binaries);
  } catch (err) {
    console.error(err.message);
    process.exitCode = 1;
  }
}

module.exports = { stage, targets };
