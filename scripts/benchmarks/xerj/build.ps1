[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path
$SpikeRoot = Join-Path $RepoRoot '.cache/xerj-spike'
$Source = Join-Path $SpikeRoot 'source'
$Output = Join-Path $SpikeRoot 'bin'
$Revision = '35ccd192508027cccc1b3e69f3b6721cb17cac64'
New-Item -ItemType Directory -Force -Path $Output | Out-Null
function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program exited with $LASTEXITCODE" }
}
if (-not (Test-Path -LiteralPath (Join-Path $Source '.git'))) {
    Invoke-Checked git @('init', $Source)
    Invoke-Checked git @('-C', $Source, 'remote', 'add', 'origin', 'https://github.com/xerj-org/xerj.git')
    Invoke-Checked git @('-C', $Source, 'fetch', '--depth=1', '--filter=blob:none', 'origin', $Revision)
    Invoke-Checked git @('-C', $Source, 'config', 'core.autocrlf', 'false')
    Invoke-Checked git @('-C', $Source, 'sparse-checkout', 'init', '--cone')
    Invoke-Checked git @('-C', $Source, 'sparse-checkout', 'set', 'engine', 'xerj-ux')
    Invoke-Checked git @('-C', $Source, 'checkout', '--detach', $Revision)
}
if ((& git -C $Source rev-parse HEAD) -ne $Revision) { throw 'Unexpected Xerj source revision' }
if (& git -C $Source status --porcelain --untracked-files=no) { throw 'Xerj source has modifications' }
Invoke-Checked docker @('build', '--tag', 'minipod-xerj-builder:35ccd192', $PSScriptRoot)
Invoke-Checked docker @('run', '--rm', '--name', 'minipod-xerj-build-35ccd192', '--cpus', '6', '--memory', '16g',
    '--mount', "type=bind,source=$Source,target=/src,readonly",
    '--mount', "type=bind,source=$PSScriptRoot,target=/harness,readonly",
    '--mount', "type=bind,source=$Output,target=/out",
    '--mount', 'type=volume,source=minipod-xerj-build-35ccd192,target=/build',
    'minipod-xerj-builder:35ccd192', 'sh', '/harness/build.sh')
Invoke-Checked docker @('run', '--rm', '--network', 'none',
    '--mount', "type=bind,source=$PSScriptRoot,target=/harness,readonly",
    '--mount', "type=bind,source=$Output,target=/out",
    'minipod-xerj-builder:35ccd192', 'sh', '/harness/build-guest.sh')
$BuildManifest = @{
    source_revision = $Revision
    xerj_sha256 = (Get-FileHash -Algorithm SHA256 (Join-Path $Output 'xerj')).Hash.ToLowerInvariant()
    cargo_lock_sha256 = (Get-FileHash -Algorithm SHA256 (Join-Path $Source 'engine/Cargo.lock')).Hash.ToLowerInvariant()
    builder_image = (& docker image inspect minipod-xerj-builder:35ccd192 --format '{{.Id}}')
    rust_base = 'rust:alpine@sha256:2cccd8b212b37dad15a555589c1b6787da4ab913fe24d8a9b2d99d3498869409'
    target = 'x86_64-unknown-linux-musl'
    rustflags = '-C target-cpu=x86-64 -C target-feature=+crt-static'
    features = '--no-default-features'
    release_lto = 'thin'
    release_codegen_units = 16
}
$BuildManifest | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Output 'build.json') -Encoding utf8
