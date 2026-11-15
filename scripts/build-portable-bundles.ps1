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

for fs_tool_name in e2fsck resize2fs; do
    fs_tool=""
    for candidate in "/sbin/$fs_tool_name" "/usr/sbin/$fs_tool_name"; do
        if [ -x "$candidate" ]; then
            fs_tool="$candidate"
            break
        fi
    done
    if [ -z "$fs_tool" ]; then
        echo "ERROR: required initramfs tool '$fs_tool_name' missing" >&2
        exit 1
    fi
    rm -f "$INITRAMFS/sbin/$fs_tool_name"
    cp -L "$fs_tool" "$INITRAMFS/sbin/$fs_tool_name"
    chmod 0755 "$INITRAMFS/sbin/$fs_tool_name"
    ldd "$fs_tool" 2>/dev/null | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^\//) print $i }' | sort -u | while IFS= read -r lib_path; do
        if [ -f "$lib_path" ]; then
            mkdir -p "$INITRAMFS$(dirname "$lib_path")"
            if [ ! -e "$INITRAMFS$lib_path" ]; then
                cp -L "$lib_path" "$INITRAMFS$lib_path"
                chmod 0755 "$INITRAMFS$lib_path"
            fi
        fi
    done
done
chroot "$INITRAMFS" /sbin/e2fsck -V >/dev/null 2>&1
if ! chroot "$INITRAMFS" /sbin/resize2fs 2>&1 | grep -qi "usage"; then
    echo "ERROR: /sbin/resize2fs failed runtime check inside initramfs chroot" >&2
    exit 1
fi

cp /out/bin/tiny-init "$INITRAMFS/init"
chmod 0755 "$INITRAMFS/init"
chmod 1777 "$INITRAMFS/tmp"

cp /lib/modules/"$KVER"/modules.* "$INITRAMFS/lib/modules/$KVER/"
for mod in virtio virtio_ring virtio_pci virtio_mmio virtio_console virtio_blk ext4 overlay \
    tun veth bridge br_netfilter nf_conntrack nf_nat ip_tables iptable_nat iptable_filter iptable_mangle iptable_raw \
    ip6_tables ip6table_nat ip6table_filter nf_tables nft_compat nft_ct nft_nat nft_chain_nat nft_masq nft_reject nft_reject_inet \
    xt_MASQUERADE xt_nat xt_addrtype xt_comment xt_conntrack xt_mark xt_multiport xt_tcpudp xt_state; do
    modprobe -d / -S "$KVER" -D "$mod" 2>/dev/null | awk '$1=="insmod"{print $2}' | while IFS= read -r modpath; do
        rel="${modpath#*/lib/modules/$KVER/}"
        if [ "$rel" != "$modpath" ] && [ -f "/lib/modules/$KVER/$rel" ]; then
            mkdir -p "$INITRAMFS/lib/modules/$KVER/$(dirname "$rel")"
            cp "/lib/modules/$KVER/$rel" "$INITRAMFS/lib/modules/$KVER/$rel"
        fi
    done
done
depmod -b "$INITRAMFS" "$KVER"

for req_mod in virtio_blk ext4 overlay tun veth bridge; do
    if ! grep -Eq "(^|/)${req_mod}\.ko" "$INITRAMFS/lib/modules/$KVER/modules.dep" && \
       ! grep -Eq "(^|/)${req_mod}\.ko" "$INITRAMFS/lib/modules/$KVER/modules.builtin"; then
        echo "ERROR: required kernel module '$req_mod' missing from initramfs modules.dep/builtin" >&2
        exit 1
    fi
done
for opt_mod in br_netfilter nf_conntrack nf_nat ip_tables iptable_nat iptable_filter iptable_mangle iptable_raw \
    ip6_tables ip6table_nat ip6table_filter nf_tables nft_compat nft_ct nft_nat nft_chain_nat nft_masq nft_reject nft_reject_inet \
    xt_MASQUERADE xt_nat xt_addrtype xt_comment xt_conntrack xt_mark xt_multiport xt_tcpudp xt_state; do
    if ! grep -Eq "(^|/)${opt_mod}\.ko" "$INITRAMFS/lib/modules/$KVER/modules.dep" && \
       ! grep -Eq "(^|/)${opt_mod}\.ko" "$INITRAMFS/lib/modules/$KVER/modules.builtin"; then
        echo "WARN: netfilter kernel module '$opt_mod' not present in modules.dep/builtin" >&2
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
    "$DISKTREE/rootfs/etc/apk" \
    "$DISKTREE/rw/etc-upper" \
    "$DISKTREE/rw/etc-work" \
    "$DISKTREE/rw/containers" \
    "$DISKTREE/rw/cni" \
    "$DISKTREE/rw/workspace" \
    "$DISKTREE/rw/tmp" \
    "$DISKTREE/rw/var-tmp" \
    "$DISKTREE/rw/root"

cp /etc/apk/repositories "$DISKTREE/rootfs/etc/apk/repositories"
cp -a /etc/apk/keys "$DISKTREE/rootfs/etc/apk/keys"

apk --root "$DISKTREE/rootfs" --initdb --no-cache --no-scripts add \
    alpine-baselayout busybox podman crun conmon catatonit netavark aardvark-dns iptables ip6tables >/dev/null

PODMAN_PKG=$(apk --root "$DISKTREE/rootfs" list -I podman | awk 'NR==1 {print $1}')
CRUN_PKG=$(apk --root "$DISKTREE/rootfs" list -I crun | awk 'NR==1 {print $1}')
if [ -z "$PODMAN_PKG" ] || [ -z "$CRUN_PKG" ]; then
    echo "ERROR: failed to query rootfs Podman/crun package versions" >&2
    exit 1
fi
echo "MINIPOD_PIN podman_pkg=$PODMAN_PKG"
echo "MINIPOD_PIN crun_pkg=$CRUN_PKG"

rm -rf \
    "$DISKTREE/rootfs/lib/apk" \
    "$DISKTREE/rootfs/var/cache/apk" \
    "$DISKTREE/rootfs/etc/apk"

chroot "$DISKTREE/rootfs" /bin/busybox --install -s || true
if [ ! -x "$DISKTREE/rootfs/bin/sh" ] || [ ! -x "$DISKTREE/rootfs/usr/bin/podman" ] || [ ! -x "$DISKTREE/rootfs/usr/bin/crun" ]; then
    echo "ERROR: rootfs missing busybox sh, podman, or crun after apk install" >&2
    exit 1
fi

mkdir -p \
    "$DISKTREE/rootfs/bin" \
    "$DISKTREE/rootfs/sbin" \
    "$DISKTREE/rootfs/etc/containers" \
    "$DISKTREE/rootfs/proc" \
    "$DISKTREE/rootfs/sys" \
    "$DISKTREE/rootfs/dev" \
    "$DISKTREE/rootfs/run" \
    "$DISKTREE/rootfs/tmp" \
    "$DISKTREE/rootfs/var/tmp" \
    "$DISKTREE/rootfs/var/lib/containers" \
    "$DISKTREE/rootfs/var/lib/cni" \
    "$DISKTREE/rootfs/workspace" \
    "$DISKTREE/rootfs/root"

if [ -d "$DISKTREE/rootfs/var/run" ] && [ ! -L "$DISKTREE/rootfs/var/run" ]; then
    rm -rf "$DISKTREE/rootfs/var/run"
fi
ln -sfn /run "$DISKTREE/rootfs/var/run"

cp /out/bin/tiny-init "$DISKTREE/rootfs/sbin/tiny-init"
chmod 0755 "$DISKTREE/rootfs/sbin/tiny-init"
cp /out/bin/sandbox-agent "$DISKTREE/rootfs/bin/sandbox-agent"
chmod 0755 "$DISKTREE/rootfs/bin/sandbox-agent"

if [ ! -f "$DISKTREE/rootfs/etc/passwd" ]; then
    cat <<'EOF' > "$DISKTREE/rootfs/etc/passwd"
root:x:0:0:root:/root:/bin/sh
EOF
fi
if [ ! -f "$DISKTREE/rootfs/etc/group" ]; then
    cat <<'EOF' > "$DISKTREE/rootfs/etc/group"
root:x:0:
EOF
fi
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

cat <<'EOF' > "$DISKTREE/rootfs/etc/containers/containers.conf"
[engine]
cgroup_manager = "cgroupfs"
events_logger = "file"
runtime = "crun"

[network]
network_backend = "netavark"
firewall_driver = "iptables"
EOF
cat <<'EOF' > "$DISKTREE/rootfs/etc/containers/storage.conf"
[storage]
driver = "overlay"
runroot = "/run/containers/storage"
graphroot = "/var/lib/containers/storage"
EOF
cat <<'EOF' > "$DISKTREE/rootfs/etc/containers/policy.json"
{
  "default": [
    {
      "type": "insecureAcceptAnything"
    }
  ]
}
EOF
cat <<'EOF' > "$DISKTREE/rootfs/etc/containers/registries.conf"
unqualified-search-registries = ["docker.io"]
EOF

chmod 0644 \
    "$DISKTREE/rootfs/etc/passwd" \
    "$DISKTREE/rootfs/etc/group" \
    "$DISKTREE/rootfs/etc/hosts" \
    "$DISKTREE/rootfs/etc/resolv.conf" \
    "$DISKTREE/rootfs/etc/os-release" \
    "$DISKTREE/rootfs/etc/containers/containers.conf" \
    "$DISKTREE/rootfs/etc/containers/storage.conf" \
    "$DISKTREE/rootfs/etc/containers/policy.json" \
    "$DISKTREE/rootfs/etc/containers/registries.conf"

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
    -d "$DISKTREE" /tmp/base.raw 256M

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

qemu-img convert -c -m 1 -f raw -O qcow2 -o compat=1.1,cluster_size=65536,lazy_refcounts=off \
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
    $PodmanPkg = $null
    $CrunPkg = $null
    foreach ($Line in $AssembleLines) {
        if ($Line -match '^MINIPOD_PIN linux_virt_pkg=(.+)$') {
            $LinuxVirtPkg = $Matches[1].Trim()
        } elseif ($Line -match '^MINIPOD_PIN busybox_static_pkg=(.+)$') {
            $BusyboxStaticPkg = $Matches[1].Trim()
        } elseif ($Line -match '^MINIPOD_PIN podman_pkg=(.+)$') {
            $PodmanPkg = $Matches[1].Trim()
        } elseif ($Line -match '^MINIPOD_PIN crun_pkg=(.+)$') {
            $CrunPkg = $Matches[1].Trim()
        }
    }
    if ([string]::IsNullOrWhiteSpace($LinuxVirtPkg) -or
        [string]::IsNullOrWhiteSpace($BusyboxStaticPkg) -or
        [string]::IsNullOrWhiteSpace($PodmanPkg) -or
        [string]::IsNullOrWhiteSpace($CrunPkg)) {
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
        --pin "podman_pkg=$PodmanPkg" `
        --pin "crun_pkg=$CrunPkg" `
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
