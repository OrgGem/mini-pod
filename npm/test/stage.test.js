'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { stage, targets } = require('../scripts/stage');
const main = require('../package.json');

function tempDir(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'mini-pod-npm-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

test('main package stages executable shims and target-matched optional dependencies', t => {
  const root = tempDir(t);
  const destination = path.join(root, 'main');
  stage('main', `${main.version}-rc.1`, destination);

  const manifest = JSON.parse(fs.readFileSync(path.join(destination, 'package.json'), 'utf8'));
  assert.equal(manifest.version, `${main.version}-rc.1`);
  assert.equal(manifest.bin['sandbox-cli'], 'bin/sandbox-cli.js');
  assert.equal(manifest.bin.sandboxd, 'bin/sandboxd.js');
  assert.deepEqual(Object.keys(manifest.optionalDependencies), Object.keys(main.optionalDependencies));
  assert.ok(Object.values(manifest.optionalDependencies).every(version => version === manifest.version));
  for (const file of ['bin/sandbox-cli.js', 'bin/sandboxd.js', 'launcher.js', 'README.md']) {
    assert.ok(fs.existsSync(path.join(destination, file)), `${file} should be staged`);
  }
});

test('platform package metadata restricts OS, CPU, and Linux libc', t => {
  for (const [target, [platform, arch]] of Object.entries(targets)) {
    const root = tempDir(t);
    const binaries = path.join(root, 'binaries');
    const destination = path.join(root, 'package');
    fs.mkdirSync(binaries);
    for (const command of ['sandbox-cli', 'sandboxd']) {
      fs.writeFileSync(path.join(binaries, command + (platform === 'win32' ? '.exe' : '')), 'fixture');
    }

    stage(target, main.version, destination, binaries);
    const manifest = JSON.parse(fs.readFileSync(path.join(destination, 'package.json'), 'utf8'));
    assert.deepEqual(manifest.os, [platform]);
    assert.deepEqual(manifest.cpu, [arch]);
    if (platform === 'linux') assert.deepEqual(manifest.libc, ['glibc']);
    else assert.equal('libc' in manifest, false);
    assert.ok(fs.existsSync(path.join(destination, 'bin', `sandboxd${platform === 'win32' ? '.exe' : ''}`)));
  }
});

test('staging rejects unrelated workspace versions and incomplete target input', t => {
  const root = tempDir(t);
  assert.throws(() => stage('main', '99.0.0', path.join(root, 'main')), /Expected version/);
  assert.throws(() => stage('x86_64-unknown-linux-gnu', main.version, path.join(root, 'linux')), /missing binary directory/i);
});
