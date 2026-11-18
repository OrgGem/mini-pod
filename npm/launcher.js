'use strict';

const path = require('node:path');
const { spawnSync } = require('node:child_process');

const packages = new Set([
  'win32-x64',
  'linux-x64',
  'linux-arm64',
  'darwin-x64',
  'darwin-arm64',
]);

function platformPackage(platform, arch, glibcVersion) {
  const target = `${platform}-${arch}`;
  if (!packages.has(target)) {
    throw new Error(`Unsupported platform: ${target}`);
  }
  if (platform === 'linux' && !glibcVersion) {
    throw new Error('Linux binaries require glibc; musl/Alpine is not supported.');
  }
  return `@orggem/mini-pod-${target}`;
}

function run(command) {
  try {
    const glibcVersion = process.platform === 'linux'
      ? process.report.getReport().header.glibcVersionRuntime
      : undefined;
    const packageName = platformPackage(process.platform, process.arch, glibcVersion);
    let packageJson;
    try {
      packageJson = require.resolve(`${packageName}/package.json`);
    } catch (err) {
      if (err.code !== 'MODULE_NOT_FOUND') throw err;
      throw new Error(`The ${packageName} binary package is missing. Reinstall with optional dependencies enabled.`);
    }
    const executable = path.join(path.dirname(packageJson), 'bin', command + (process.platform === 'win32' ? '.exe' : ''));
    const result = spawnSync(executable, process.argv.slice(2), { stdio: 'inherit' });
    if (result.error) throw result.error;
    if (result.signal) {
      process.kill(process.pid, result.signal);
    } else {
      process.exitCode = result.status ?? 1;
    }
  } catch (err) {
    console.error(`${command}: ${err.message}`);
    process.exitCode = 1;
  }
}

module.exports = { platformPackage, run };
