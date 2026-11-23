'use strict';

const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

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

function shouldForwardSignal(platform, signal, win32SigintCount) {
  if (platform !== 'win32') {
    return true;
  }
  // On Windows inherited console `Ctrl+C` delivers `CTRL_C_EVENT` directly to the Rust child
  // so it can clean up VMs and exit with code 130; `child.kill` calls `TerminateProcess` (hard kill).
  // Let the first `SIGINT` pass gracefully and escalate on repeat `SIGINT` or `SIGTERM`.
  if (signal === 'SIGINT') {
    return win32SigintCount > 1;
  }
  if (signal === 'SIGHUP') {
    return false;
  }
  return true;
}

function exitCodeForSignal(signal) {
  const signo = os.constants.signals[signal];
  return typeof signo === 'number' ? 128 + signo : 1;
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
    const child = spawn(executable, process.argv.slice(2), { stdio: 'inherit' });
    let win32SigintCount = 0;
    const signalHandlers = [];
    for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
      const handler = () => {
        if (process.platform === 'win32' && sig === 'SIGINT') {
          win32SigintCount += 1;
        }
        if (
          child.exitCode === null
          && child.signalCode === null
          && shouldForwardSignal(process.platform, sig, win32SigintCount)
        ) {
          try {
            child.kill(sig);
          } catch {
            // Ignore errors if the child already exited between check and signal delivery.
          }
        }
      };
      signalHandlers.push([sig, handler]);
      process.on(sig, handler);
    }
    const cleanupSignals = () => {
      for (const [sig, handler] of signalHandlers) {
        process.off(sig, handler);
      }
    };

    child.on('error', err => {
      cleanupSignals();
      console.error(`${command}: ${err.message}`);
      process.exitCode = 1;
    });

    child.on('exit', (code, signal) => {
      cleanupSignals();
      if (signal) {
        process.exitCode = exitCodeForSignal(signal);
        if (process.platform !== 'win32') {
          try {
            process.kill(process.pid, signal);
          } catch {
            // Fall back to `process.exitCode` set above if signal re-delivery fails.
          }
        }
      } else {
        process.exitCode = code ?? 1;
      }
    });
  } catch (err) {
    console.error(`${command}: ${err.message}`);
    process.exitCode = 1;
  }
}

module.exports = { platformPackage, run, shouldForwardSignal, exitCodeForSignal };
