<#
.SYNOPSIS
Reproducibly builds and signs Portable Runtime Bundles for x86_64 and aarch64
using pinned rust:alpine and alpine:3.20 multi-arch Docker containers.

.DESCRIPTION
Outputs signed bundles to <OutDir>\<arch> (default: <repo>\.cache\bundles-src\<arch>):
  - kernel/vmlinuz-virt
  - boot/initramfs.cpio.gz
  - rootfs/base.qcow2
  - bin/tiny-init
  - bin/sandbox-agent
  - manifest.v1 / manifest.sig (signed using <KeyDir>\dev-bundle.key)
#>
[CmdletBinding()]
param(
    [string]$OutDir = "",
    [string]$KeyDir = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $RepoRoot ".cache\bundles-src"
}
if ([string]::IsNullOrWhiteSpace($KeyDir)) {
    $KeyDir = Join-Path $RepoRoot ".cache\keys"
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
New-Item -ItemType Directory -Force -Path $KeyDir | Out-Null
$ResolvedOutDir = (Resolve-Path $OutDir).Path
$ResolvedKeyDir = (Resolve-Path $KeyDir).Path

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "docker CLI not found in PATH; Docker is required to build Portable Runtime Bundles."
}

$RustAlpineDigest = "sha256:2cccd8b212b37dad15a555589c1b6787da4ab913fe24d8a9b2d99d3498869409"
$AlpineDigest = "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
$RustAlpineImage = "rust:alpine@$RustAlpineDigest"
$AlpineImage = "alpine:3.20@$AlpineDigest"

$SourceDateEpoch = "1704067200"
$Ext4Uuid = "00000000-0000-4000-8000-000000000001"
$Ext4HashSeed = "00000000-0000-4000-8000-000000000002"

function Invoke-DockerShell {
    param(
        [Parameter(Mandatory = $true)][string]$Platform,
        [Parameter(Mandatory = $true)][string]$Image,
        [Parameter(Mandatory = $true)][string[]]$DockerArgsExtra,
        [Parameter(Mandatory = $true)][string]$Script
    )

    # Base64-encode LF script over stdin so PowerShell pipeline CRLF and argv quoting never touch it.
    $UnixScript = $Script.Replace("`r`n", "`n")
    $Encoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($UnixScript))
    $DockerArgs = @("run", "--rm", "-i", "--platform", $Platform) + $DockerArgsExtra + @(
        $Image,
        "sh",
        "-c",
        "base64 -d > /tmp/build.sh && exec sh -eu /tmp/build.sh"
    )
    $Lines = @($Encoded | & docker @DockerArgs | ForEach-Object {
        Write-Host $_
        $_
    })
    if ($LASTEXITCODE -ne 0) {
        throw "Docker build step failed in image '$Image' ($Platform) with exit code $LASTEXITCODE."
    }
    return ,$Lines
}

$SecretKeyPath = Join-Path $ResolvedKeyDir "dev-bundle.key"
$PublicKeyPath = Join-Path $ResolvedKeyDir "dev-bundle.pub"
$HasSecret = Test-Path $SecretKeyPath
$HasPublic = Test-Path $PublicKeyPath
if ($HasSecret -xor $HasPublic) {
    throw "Incomplete dev keypair in '$ResolvedKeyDir': both dev-bundle.key and dev-bundle.pub must exist together or neither must exist."
}
if (-not ($HasSecret -and $HasPublic)) {
    Write-Host "[0/2] Generating Ed25519 bundle dev keypair in '$ResolvedKeyDir'..."
    & cargo run --manifest-path "$RepoRoot\Cargo.toml" --locked --package sandbox-image --bin bundle-pack -- `
        --generate-keypair $SecretKeyPath $PublicKeyPath
    if ($LASTEXITCODE -ne 0) {
        throw "bundle-pack --generate-keypair failed with exit code $LASTEXITCODE."
    }
} else {
    Write-Host "[0/2] Reusing existing Ed25519 bundle keypair in '$ResolvedKeyDir'."
}

$BuildGuestBinsScript = @'
set -eu
umask 022
apk add --no-cache musl-dev file binutils >/dev/null

export RUSTFLAGS="-C target-feature=+crt-static"
cargo build \
    --manifest-path /src/Cargo.toml \
    --locked \
    --package tiny-init \
    --package sandbox-agent \
    --bin tiny-init \
    --bin sandbox-agent \
    --target-dir /tmp/cargo-target \
    --profile guest-release

mkdir -p /out/bin
for bin in tiny-init sandbox-agent; do
    src="/tmp/cargo-target/guest-release/$bin"
    dst="/out/bin/$bin"
    cp "$src" "$dst"
    chmod 0755 "$dst"

    FILE_INFO=$(file "$dst")
    echo "$bin: $FILE_INFO"
    case "$TARGET_ARCH" in
        x86_64)
            echo "$FILE_INFO" | grep -q "x86-64" || {
                echo "ERROR: $bin is not x86-64 ELF: $FILE_INFO" >&2
                exit 1
            }
            ;;
        aarch64)
            echo "$FILE_INFO" | grep -q "ARM aarch64" || {
                echo "ERROR: $bin is not ARM aarch64 ELF: $FILE_INFO" >&2
                exit 1
            }
            ;;
        *)
            echo "ERROR: unsupported TARGET_ARCH '$TARGET_ARCH'" >&2
            exit 1
            ;;
    esac
    echo "$FILE_INFO" | grep -Eq "statically linked|static-pie linked" || {
        echo "ERROR: $bin must be statically linked" >&2
        exit 1
    }
    if echo "$FILE_INFO" | grep -q "interpreter"; then
        echo "ERROR: $bin must not reference a dynamic ELF interpreter" >&2
        exit 1
    fi
    if readelf -l "$dst" 2>&1 | grep -q "INTERP"; then
        echo "ERROR: $bin must not contain a PT_INTERP segment" >&2
        exit 1
    fi
    if readelf -d "$dst" 2>&1 | grep -q "(NEEDED)"; then
        echo "ERROR: $bin has unexpected shared library dependencies:" >&2
        readelf -d "$dst" >&2
        exit 1
    fi
    SIZE_BYTES=$(stat -c '%s' "$dst")
    echo "$bin exact size ($TARGET_ARCH): $SIZE_BYTES bytes (BRD target ~2097152 bytes)"
done
'@

$AssembleBundleScript = @'
set -eu
umask 022
apk add --no-cache linux-virt busybox-static kmod cpio gzip file e2fsprogs e2fsprogs-extra qemu-img >/dev/null

LINUX_VIRT_PKG=$(apk list -I linux-virt | awk 'NR==1 {print $1}')
BUSYBOX_STATIC_PKG=$(apk list -I busybox-static | awk 'NR==1 {print $1}')
if [ -z "$LINUX_VIRT_PKG" ] || [ -z "$BUSYBOX_STATIC_PKG" ]; then
    echo "ERROR: failed to query Alpine package versions" >&2
    exit 1
fi
echo "MINIPOD_PIN linux_virt_pkg=$LINUX_VIRT_PKG"
echo "MINIPOD_PIN busybox_static_pkg=$BUSYBOX_STATIC_PKG"

KVER=$(ls /lib/modules | head -n 1)
if [ -z "$KVER" ]; then
    echo "ERROR: no kernel modules directory found under /lib/modules" >&2
    exit 1
fi
echo "Kernel version ($TARGET_ARCH): $KVER"

mkdir -p /out/kernel /out/boot /out/rootfs
case "$TARGET_ARCH" in
    x86_64)
        cp /boot/vmlinuz-virt /out/kernel/vmlinuz-virt
        file /out/kernel/vmlinuz-virt | grep -q "Linux kernel x86 boot executable"
        ;;
    aarch64)
        # Alpine aarch64 linux-virt is an EFI PE32+ zimg container; extract the inner Image.gz.
        OFF=$(od -An -tu4 -j 8 -N 4 /boot/vmlinuz-virt | tr -d ' ')
        SZ=$(od -An -tu4 -j 12 -N 4 /boot/vmlinuz-virt | tr -d ' ')
        if [ -z "$OFF" ] || [ -z "$SZ" ] || [ "$OFF" -le 0 ] || [ "$SZ" -le 0 ]; then
            echo "ERROR: invalid EFI zimg header offsets (OFF=$OFF SZ=$SZ)" >&2
            exit 1
        fi
        dd if=/boot/vmlinuz-virt iflag=skip_bytes,count_bytes skip="$OFF" count="$SZ" of=/out/kernel/vmlinuz-virt 2>/dev/null
        file /out/kernel/vmlinuz-virt | grep -q "gzip compressed data"
        gzip -dc /out/kernel/vmlinuz-virt | file - | grep -q "Linux kernel ARM64 boot executable Image"
        ;;
    *)
        echo "ERROR: unsupported TARGET_ARCH '$TARGET_ARCH'" >&2
        exit 1
        ;;
esac
chmod 0644 /out/kernel/vmlinuz-virt

INITRAMFS="/tmp/initramfs"
rm -rf "$INITRAMFS"
mkdir -p \
    "$INITRAMFS/bin" \
    "$INITRAMFS/sbin" \
    "$INITRAMFS/usr/bin" \
    "$INITRAMFS/usr/sbin" \
    "$INITRAMFS/proc" \
    "$INITRAMFS/sys" \
    "$INITRAMFS/dev" \
    "$INITRAMFS/dev/virtio-ports" \
    "$INITRAMFS/run" \
    "$INITRAMFS/mnt/disk" \
    "$INITRAMFS/newroot" \
    "$INITRAMFS/tmp" \
    "$INITRAMFS/lib/modules/$KVER"

cp /bin/busybox.static "$INITRAMFS/bin/busybox"
chmod 0755 "$INITRAMFS/bin/busybox"
chroot "$INITRAMFS" /bin/busybox --install -s

cp /out/bin/tiny-init "$INITRAMFS/init"
chmod 0755 "$INITRAMFS/init"
chmod 1777 "$INITRAMFS/tmp"

cp /lib/modules/"$KVER"/modules.* "$INITRAMFS/lib/modules/$KVER/"
for mod in virtio virtio_ring virtio_pci virtio_mmio virtio_console virtio_blk ext4 overlay; do
    modprobe -d / -S "$KVER" -D "$mod" 2>/dev/null | awk '$1=="insmod"{print $2}' | while IFS= read -r modpath; do
        rel="${modpath#*/lib/modules/$KVER/}"
        if [ "$rel" != "$modpath" ] && [ -f "/lib/modules/$KVER/$rel" ]; then
            mkdir -p "$INITRAMFS/lib/modules/$KVER/$(dirname "$rel")"
            cp "/lib/modules/$KVER/$rel" "$INITRAMFS/lib/modules/$KVER/$rel"
        fi
    done
done
depmod -b "$INITRAMFS" "$KVER"

for req_mod in virtio_blk ext4 overlay; do
    if ! grep -Eq "(^|/)${req_mod}\.ko" "$INITRAMFS/lib/modules/$KVER/modules.dep" && \
       ! grep -Eq "(^|/)${req_mod}\.ko" "$INITRAMFS/lib/modules/$KVER/modules.builtin"; then
        echo "ERROR: required kernel module '$req_mod' missing from initramfs modules.dep/builtin" >&2
        exit 1
    fi
done

find "$INITRAMFS" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
(
    cd "$INITRAMFS"
    find . -print0 | LC_ALL=C sort -z | cpio --null -o -H newc -R 0:0 --reproducible | gzip -n -9 > /out/boot/initramfs.cpio.gz
)
chmod 0644 /out/boot/initramfs.cpio.gz

DISKTREE="/tmp/disktree"
rm -rf "$DISKTREE" /tmp/base.raw
mkdir -p \
    "$DISKTREE/rootfs/bin" \
    "$DISKTREE/rootfs/sbin" \
    "$DISKTREE/rootfs/usr/bin" \
    "$DISKTREE/rootfs/usr/sbin" \
    "$DISKTREE/rootfs/etc" \
    "$DISKTREE/rootfs/proc" \
    "$DISKTREE/rootfs/sys" \
    "$DISKTREE/rootfs/dev" \
    "$DISKTREE/rootfs/run" \
    "$DISKTREE/rootfs/tmp" \
    "$DISKTREE/rootfs/var/tmp" \
    "$DISKTREE/rootfs/var/lib/containers" \
    "$DISKTREE/rootfs/workspace" \
    "$DISKTREE/rootfs/root" \
    "$DISKTREE/rw/etc-upper" \
    "$DISKTREE/rw/etc-work" \
    "$DISKTREE/rw/containers" \
    "$DISKTREE/rw/workspace" \
    "$DISKTREE/rw/tmp" \
    "$DISKTREE/rw/var-tmp" \
    "$DISKTREE/rw/root"

cp /bin/busybox.static "$DISKTREE/rootfs/bin/busybox"
chmod 0755 "$DISKTREE/rootfs/bin/busybox"
chroot "$DISKTREE/rootfs" /bin/busybox --install -s

cp /out/bin/tiny-init "$DISKTREE/rootfs/sbin/tiny-init"
chmod 0755 "$DISKTREE/rootfs/sbin/tiny-init"
cp /out/bin/sandbox-agent "$DISKTREE/rootfs/bin/sandbox-agent"
chmod 0755 "$DISKTREE/rootfs/bin/sandbox-agent"

cat <<'EOF' > "$DISKTREE/rootfs/etc/passwd"
root:x:0:0:root:/root:/bin/sh
EOF
cat <<'EOF' > "$DISKTREE/rootfs/etc/group"
root:x:0:
EOF
cat <<'EOF' > "$DISKTREE/rootfs/etc/hosts"
127.0.0.1 localhost
::1 localhost
EOF
cat <<'EOF' > "$DISKTREE/rootfs/etc/resolv.conf"
# isolated guest
EOF
cat <<'EOF' > "$DISKTREE/rootfs/etc/os-release"
NAME="mini-pod"
ID=minipod
VERSION_ID=1
PRETTY_NAME="mini-pod Alpine Linux Guest"
EOF

chmod 0644 \
    "$DISKTREE/rootfs/etc/passwd" \
    "$DISKTREE/rootfs/etc/group" \
    "$DISKTREE/rootfs/etc/hosts" \
    "$DISKTREE/rootfs/etc/resolv.conf" \
    "$DISKTREE/rootfs/etc/os-release"

chmod 1777 \
    "$DISKTREE/rootfs/tmp" \
    "$DISKTREE/rootfs/var/tmp" \
    "$DISKTREE/rw/tmp" \
    "$DISKTREE/rw/var-tmp"
chmod 0700 \
    "$DISKTREE/rootfs/root" \
    "$DISKTREE/rw/root"

find "$DISKTREE" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

mkfs.ext4 -q -F -b 4096 -L minipod-root \
    -U "$EXT4_UUID" \
    -E "root_owner=0:0,hash_seed=${EXT4_HASH_SEED},lazy_itable_init=0,lazy_journal_init=0" \
    -d "$DISKTREE" /tmp/base.raw 64M

# `mke2fs -d` honors `E2FSPROGS_FAKE_TIME` for root/atime/mtime/crtime, but copies host `st_ctime`
# for tree-populated inodes. Normalize every inode `ctime` deterministically with `debugfs`.
{
    printf 'sif <2> ctime %s\nsif <2> ctime_extra 0\n' "$SOURCE_DATE_EPOCH"
    printf 'sif <11> ctime %s\nsif <11> ctime_extra 0\n' "$SOURCE_DATE_EPOCH"
    (
        cd "$DISKTREE"
        find . -mindepth 1 | LC_ALL=C sort | while IFS= read -r rel; do
            fs_path="/${rel#./}"
            printf 'sif "%s" ctime %s\nsif "%s" ctime_extra 0\n' "$fs_path" "$SOURCE_DATE_EPOCH" "$fs_path"
        done
    )
} > /tmp/debugfs-cmds
debugfs -w -f /tmp/debugfs-cmds /tmp/base.raw >/tmp/debugfs.out 2>&1
if grep -v '^debugfs: sif ' /tmp/debugfs.out | grep -qiE 'error|usage|not found|invalid|cannot'; then
    cat /tmp/debugfs.out >&2
    exit 1
fi
rm -f /tmp/debugfs-cmds /tmp/debugfs.out
e2fsck -fn /tmp/base.raw >/dev/null

qemu-img convert -f raw -O qcow2 -o compat=1.1,cluster_size=65536,lazy_refcounts=off \
    /tmp/base.raw /out/rootfs/base.qcow2
chmod 0644 /out/rootfs/base.qcow2
rm -f /tmp/base.raw

ls -lh /out/kernel/vmlinuz-virt /out/boot/initramfs.cpio.gz /out/rootfs/base.qcow2 /out/bin/tiny-init /out/bin/sandbox-agent
'@

$Targets = @(
    @{ Arch = "x86_64";  Platform = "linux/amd64" },
    @{ Arch = "aarch64"; Platform = "linux/arm64" }
)

foreach ($Target in $Targets) {
    $Arch = $Target.Arch
    $Platform = $Target.Platform
    $ArchOutDir = Join-Path $ResolvedOutDir $Arch

    if (Test-Path $ArchOutDir) {
        Remove-Item -Recurse -Force -Path $ArchOutDir
    }
    New-Item -ItemType Directory -Force -Path $ArchOutDir | Out-Null

    Write-Host ""
    Write-Host "=== [$Arch / $Platform] Building static musl tiny-init & sandbox-agent ==="
    $CommonEnv = @(
        "-e", "TARGET_ARCH=$Arch",
        "-e", "SOURCE_DATE_EPOCH=$SourceDateEpoch",
        "-e", "TZ=UTC",
        "-e", "LC_ALL=C",
        "-e", "E2FSPROGS_FAKE_TIME=$SourceDateEpoch",
        "-e", "EXT4_UUID=$Ext4Uuid",
        "-e", "EXT4_HASH_SEED=$Ext4HashSeed"
    )
    $null = Invoke-DockerShell `
        -Platform $Platform `
        -Image $RustAlpineImage `
        -DockerArgsExtra ($CommonEnv + @("-v", "${RepoRoot}:/src:ro", "-v", "${ArchOutDir}:/out")) `
        -Script $BuildGuestBinsScript

    Write-Host "=== [$Arch / $Platform] Assembling kernel, initramfs, and rootfs base.qcow2 ==="
    $AssembleLines = Invoke-DockerShell `
        -Platform $Platform `
        -Image $AlpineImage `
        -DockerArgsExtra ($CommonEnv + @("-v", "${ArchOutDir}:/out")) `
        -Script $AssembleBundleScript

    $LinuxVirtPkg = $null
    $BusyboxStaticPkg = $null
    foreach ($Line in $AssembleLines) {
        if ($Line -match '^MINIPOD_PIN linux_virt_pkg=(.+)$') {
            $LinuxVirtPkg = $Matches[1].Trim()
        } elseif ($Line -match '^MINIPOD_PIN busybox_static_pkg=(.+)$') {
            $BusyboxStaticPkg = $Matches[1].Trim()
        }
    }
    if ([string]::IsNullOrWhiteSpace($LinuxVirtPkg) -or [string]::IsNullOrWhiteSpace($BusyboxStaticPkg)) {
        throw "Failed to capture package pins from $AlpineImage ($Platform)."
    }

    $BundleId = "minipod-linux-$Arch-v1"
    Write-Host "=== [$Arch] Packing and signing bundle '$BundleId' ==="
    & cargo run --manifest-path "$RepoRoot\Cargo.toml" --locked --package sandbox-image --bin bundle-pack -- `
        --bundle-dir $ArchOutDir `
        --bundle-id $BundleId `
        --host-os "any" `
        --guest-arch $Arch `
        --pin "rust_alpine_digest=$RustAlpineDigest" `
        --pin "alpine_digest=$AlpineDigest" `
        --pin "linux_virt_pkg=$LinuxVirtPkg" `
        --pin "busybox_static_pkg=$BusyboxStaticPkg" `
        --pin "source_date_epoch=$SourceDateEpoch" `
        --entry "kernel=kernel/vmlinuz-virt" `
        --entry "initrd=boot/initramfs.cpio.gz" `
        --entry "base_rootfs_qcow2=rootfs/base.qcow2" `
        --entry "tiny_init=bin/tiny-init" `
        --entry "guest_agent=bin/sandbox-agent" `
        --secret-key-file $SecretKeyPath
    if ($LASTEXITCODE -ne 0) {
        throw "bundle-pack failed for $Arch with exit code $LASTEXITCODE."
    }

    $TotalBytes = (Get-ChildItem -Path $ArchOutDir -Recurse -File | Measure-Object -Property Length -Sum).Sum
    $TotalMiB = [Math]::Round($TotalBytes / 1MB, 2)
    Write-Host "Bundle '$BundleId' total size: $TotalBytes bytes ($TotalMiB MiB vs BRD ~85 MB target)"
}

Write-Host ""
Write-Host "Portable Runtime Bundles built and signed in '$ResolvedOutDir'."
