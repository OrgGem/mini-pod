'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const test = require('node:test');

const { platformPackage } = require('../launcher');
const { stage } = require('../scripts/stage');
const main = require('../package.json');

function tempDir(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'mini-pod-npm-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function resolveWindowsBinaryDir() {
  const candidates = [];
  if (process.env.CARGO_TARGET_DIR) {
    candidates.push(
      path.join(process.env.CARGO_TARGET_DIR, 'release'),
      path.join(process.env.CARGO_TARGET_DIR, 'debug'),
    );
  }
  candidates.push(
    path.resolve(__dirname, '../../target/release'),
    path.resolve(__dirname, '../../target/debug'),
  );
  const found = candidates.find(dir =>
    fs.existsSync(path.join(dir, 'sandbox-cli.exe')) && fs.existsSync(path.join(dir, 'sandboxd.exe'))
  );
  if (!found) {
    throw new Error(`Could not locate sandbox-cli.exe and sandboxd.exe in: ${candidates.join(', ')}`);
  }
  return found;
}

function installFixture(root, { withBinaryPackage }) {
  const stagedMain = path.join(root, 'staged-main');
  stage('main', main.version, stagedMain);
  const installRoot = path.join(root, 'install', 'node_modules', '@orggem');
  const installedMain = path.join(installRoot, 'mini-pod');
  fs.mkdirSync(installRoot, { recursive: true });
  fs.cpSync(stagedMain, installedMain, { recursive: true });

  if (withBinaryPackage) {
    const binaryPackage = path.join(installRoot, 'mini-pod-win32-x64');
    stage('x86_64-pc-windows-msvc', main.version, binaryPackage, resolveWindowsBinaryDir());
  }
  return installedMain;
}

test('launcher maps supported platforms and requires glibc on Linux', () => {
  assert.equal(platformPackage('win32', 'x64'), '@orggem/mini-pod-win32-x64');
  assert.equal(platformPackage('darwin', 'arm64'), '@orggem/mini-pod-darwin-arm64');
  assert.equal(platformPackage('linux', 'x64', '2.35'), '@orggem/mini-pod-linux-x64');
  assert.throws(() => platformPackage('linux', 'x64', undefined), /glibc.*musl/i);
  assert.throws(() => platformPackage('linux', 'arm64', undefined), /glibc.*musl/i);
  assert.throws(() => platformPackage('win32', 'arm64'), /Unsupported platform/);
});

test('installed Windows package forwards arguments and stdio and preserves CLI exit status', { skip: process.platform !== 'win32' }, t => {
  const root = tempDir(t);
  const installedMain = installFixture(root, { withBinaryPackage: true });
  const cli = path.join(installedMain, 'bin', 'sandbox-cli.js');
  const help = spawnSync(process.execPath, [cli, '--help'], { encoding: 'utf8' });
  assert.equal(help.status, 0, help.stderr);
  assert.match(help.stdout, /USAGE:/);
  assert.match(help.stdout, /docker-endpoint/);

  const invalid = spawnSync(process.execPath, [cli, '--definitely-invalid-option'], { encoding: 'utf8' });
  assert.equal(invalid.status, 1);
  assert.match(invalid.stderr, /sandbox-cli error/i);
  assert.match(invalid.stderr, /definitely-invalid-option/);

  const daemonHelp = spawnSync(process.execPath, [path.join(installedMain, 'bin', 'sandboxd.js'), '--help'], { encoding: 'utf8' });
  assert.equal(daemonHelp.status, 0, daemonHelp.stderr);
  assert.match(daemonHelp.stdout, /serve|mcp/);
});

test('missing optional binary dependency reports an actionable install error', { skip: process.platform !== 'win32' }, t => {
  const root = tempDir(t);
  const installedMain = installFixture(root, { withBinaryPackage: false });
  const result = spawnSync(process.execPath, [path.join(installedMain, 'bin', 'sandbox-cli.js'), '--help'], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /binary package is missing/i);
  assert.match(result.stderr, /optional dependencies/i);
});

test('Unix launcher forwards spaced arguments, stdio, and the binary exit status', { skip: process.platform === 'win32' }, t => {
  const root = tempDir(t);
  const stagedMain = path.join(root, 'staged-main');
  stage('main', main.version, stagedMain);
  const installRoot = path.join(root, 'install', 'node_modules', '@orggem');
  const installedMain = path.join(installRoot, 'mini-pod');
  fs.mkdirSync(installRoot, { recursive: true });
  fs.cpSync(stagedMain, installedMain, { recursive: true });

  const glibcVersion = process.platform === 'linux'
    ? process.report.getReport().header.glibcVersionRuntime
    : undefined;
  const binaryPackageName = platformPackage(process.platform, process.arch, glibcVersion).split('/')[1];
  const binaryPackage = path.join(installRoot, binaryPackageName);
  const binaryDirectory = path.join(binaryPackage, 'bin');
  fs.mkdirSync(binaryDirectory, { recursive: true });
  fs.writeFileSync(path.join(binaryPackage, 'package.json'), JSON.stringify({ name: `@orggem/${binaryPackageName}`, version: main.version }));
  const fakeBinary = path.join(binaryDirectory, 'sandbox-cli');
  fs.writeFileSync(fakeBinary, [
    '#!/usr/bin/env node',
    'const args = process.argv.slice(2);',
    'process.stdout.write(JSON.stringify(args) + "\\n");',
    'if (args.includes("--fail")) { process.stderr.write("fake failure\\n"); process.exitCode = 7; }',
    '',
  ].join('\n'));
  fs.chmodSync(fakeBinary, 0o755);

  const result = spawnSync(process.execPath, [path.join(installedMain, 'bin', 'sandbox-cli.js'), 'a value with spaces', '--fail'], { encoding: 'utf8' });
  assert.equal(result.status, 7);
  assert.deepEqual(JSON.parse(result.stdout), ['a value with spaces', '--fail']);
  assert.equal(result.stderr, 'fake failure\n');
});

test('Unix launcher asynchronously forwards SIGTERM to spawned child', { skip: process.platform === 'win32' }, async t => {
  const root = tempDir(t);
  const stagedMain = path.join(root, 'staged-main');
  stage('main', main.version, stagedMain);
  const installRoot = path.join(root, 'install', 'node_modules', '@orggem');
  const installedMain = path.join(installRoot, 'mini-pod');
  fs.mkdirSync(installRoot, { recursive: true });
  fs.cpSync(stagedMain, installedMain, { recursive: true });

  const glibcVersion = process.platform === 'linux'
    ? process.report.getReport().header.glibcVersionRuntime
    : undefined;
  const binaryPackageName = platformPackage(process.platform, process.arch, glibcVersion).split('/')[1];
  const binaryPackage = path.join(installRoot, binaryPackageName);
  const binaryDirectory = path.join(binaryPackage, 'bin');
  fs.mkdirSync(binaryDirectory, { recursive: true });
  fs.writeFileSync(path.join(binaryPackage, 'package.json'), JSON.stringify({ name: `@orggem/${binaryPackageName}`, version: main.version }));
  const marker = path.join(root, 'sigterm.marker');
  const fakeBinary = path.join(binaryDirectory, 'sandbox-cli');
  fs.writeFileSync(fakeBinary, [
    '#!/usr/bin/env node',
    'const fs = require("node:fs");',
    `process.on("SIGTERM", () => { fs.writeFileSync(${JSON.stringify(marker)}, "caught"); process.exit(0); });`,
    'process.stdout.write("READY\\n");',
    'setInterval(() => {}, 1000);',
    '',
  ].join('\n'));
  fs.chmodSync(fakeBinary, 0o755);

  const child = spawn(process.execPath, [path.join(installedMain, 'bin', 'sandbox-cli.js')], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '';
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timed out waiting for READY, stdout=${stdout}`)), 5000);
    child.stdout.on('data', chunk => {
      stdout += chunk.toString('utf8');
      if (stdout.includes('READY\n')) {
        clearTimeout(timer);
        resolve();
      }
    });
    child.on('error', reject);
  });

  child.kill('SIGTERM');
  const [code, signal] = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timed out waiting for launcher exit')), 5000);
    child.on('exit', (c, s) => {
      clearTimeout(timer);
      resolve([c, s]);
    });
  });

  assert.equal(signal, null);
  assert.equal(code, 0);
  assert.equal(fs.readFileSync(marker, 'utf8'), 'caught');
});

test('Unix launcher forwards multiple escalating signals and propagates uncaught child signal exit', { skip: process.platform === 'win32' }, async t => {
  const root = tempDir(t);
  const stagedMain = path.join(root, 'staged-main');
  stage('main', main.version, stagedMain);
  const installRoot = path.join(root, 'install', 'node_modules', '@orggem');
  const installedMain = path.join(installRoot, 'mini-pod');
  fs.mkdirSync(installRoot, { recursive: true });
  fs.cpSync(stagedMain, installedMain, { recursive: true });

  const glibcVersion = process.platform === 'linux'
    ? process.report.getReport().header.glibcVersionRuntime
    : undefined;
  const binaryPackageName = platformPackage(process.platform, process.arch, glibcVersion).split('/')[1];
  const binaryPackage = path.join(installRoot, binaryPackageName);
  const binaryDirectory = path.join(binaryPackage, 'bin');
  fs.mkdirSync(binaryDirectory, { recursive: true });
  fs.writeFileSync(path.join(binaryPackage, 'package.json'), JSON.stringify({ name: `@orggem/${binaryPackageName}`, version: main.version }));
  const marker = path.join(root, 'escalation.marker');
  const fakeBinary = path.join(binaryDirectory, 'sandbox-cli');
  fs.writeFileSync(fakeBinary, [
    '#!/usr/bin/env node',
    'const fs = require("node:fs");',
    `const marker = ${JSON.stringify(marker)};`,
    'if (process.argv.includes("--sigkill")) { process.kill(process.pid, "SIGKILL"); }',
    'process.on("SIGINT", () => { fs.appendFileSync(marker, "sigint;"); });',
    'process.on("SIGTERM", () => { fs.appendFileSync(marker, "sigterm"); process.exit(0); });',
    'process.stdout.write("READY\\n");',
    'setInterval(() => {}, 1000);',
    '',
  ].join('\n'));
  fs.chmodSync(fakeBinary, 0o755);

  const child = spawn(process.execPath, [path.join(installedMain, 'bin', 'sandbox-cli.js')], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '';
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timed out waiting for READY, stdout=${stdout}`)), 5000);
    child.stdout.on('data', chunk => {
      stdout += chunk.toString('utf8');
      if (stdout.includes('READY\n')) {
        clearTimeout(timer);
        resolve();
      }
    });
    child.on('error', reject);
  });

  child.kill('SIGINT');
  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    if (fs.existsSync(marker) && fs.readFileSync(marker, 'utf8').includes('sigint;')) {
      break;
    }
    await new Promise(r => setTimeout(r, 20));
  }
  assert.equal(fs.readFileSync(marker, 'utf8'), 'sigint;');

  // Escalate with SIGTERM after child handled/ignored SIGINT.
  child.kill('SIGTERM');
  const [code, signal] = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timed out waiting for escalated exit')), 5000);
    child.on('exit', (c, s) => {
      clearTimeout(timer);
      resolve([c, s]);
    });
  });
  assert.equal(signal, null);
  assert.equal(code, 0);
  assert.equal(fs.readFileSync(marker, 'utf8'), 'sigint;sigterm');

  const killedRun = spawnSync(
    process.execPath,
    [path.join(installedMain, 'bin', 'sandbox-cli.js'), '--sigkill'],
    { encoding: 'utf8' },
  );
  assert.ok(killedRun.signal === 'SIGKILL' || killedRun.status === 128 + os.constants.signals.SIGKILL);
});
