<#
.SYNOPSIS
Reproducibly builds the Phase 1 spike Linux guest kernel, static musl sandbox-agent,
and BusyBox initramfs using official rust:alpine and alpine:3.20 Docker containers.

.DESCRIPTION
Outputs to <repo>\.cache\spike-guest by default:
  - sandbox-agent (statically linked x86_64 musl ELF binary)
  - vmlinuz-virt (Alpine 3.20 linux-virt kernel)
  - initramfs.cpio.gz (BusyBox-static + virtio modules + /init + /bin/sandbox-agent)
#>
[CmdletBinding()]
param(
    [string]$OutDir = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $RepoRoot ".cache\spike-guest"
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$ResolvedOutDir = (Resolve-Path $OutDir).Path

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "docker CLI not found in PATH; Docker is required to build the Linux spike guest."
}

function Invoke-DockerShell {
    param(
        [Parameter(Mandatory = $true)][string]$Image,
        [Parameter(Mandatory = $true)][string[]]$MountArgs,
        [Parameter(Mandatory = $true)][string]$Script
    )

    # Base64-encode LF script over stdin so PowerShell pipeline CRLF and argv quoting never touch it.
    $UnixScript = $Script.Replace("`r`n", "`n")
    $Encoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($UnixScript))
    $DockerArgs = @("run", "--rm", "-i") + $MountArgs + @(
        $Image,
        "sh",
        "-c",
        "base64 -d > /tmp/build.sh && exec sh -eu /tmp/build.sh"
    )
    $Encoded | & docker @DockerArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Docker build step failed in image '$Image' with exit code $LASTEXITCODE."
    }
}

Write-Host "[1/2] Building static musl sandbox-agent in rust:alpine..."
$BuildAgentScript = @'
set -eu
apk add --no-cache musl-dev file binutils >/dev/null

export RUSTFLAGS="-C target-feature=+crt-static"
cargo build \
    --manifest-path /src/Cargo.toml \
    --locked \
    --package sandbox-agent \
    --bin sandbox-agent \
    --target-dir /tmp/cargo-target \
    --profile guest-release

BIN="/tmp/cargo-target/guest-release/sandbox-agent"
cp "$BIN" /out/sandbox-agent
chmod 0755 /out/sandbox-agent

echo "=== sandbox-agent static linkage verification ==="
FILE_INFO=$(file /out/sandbox-agent)
echo "$FILE_INFO"
echo "$FILE_INFO" | grep -Eq "statically linked|static-pie linked" || {
    echo "ERROR: sandbox-agent must be statically linked" >&2
    exit 1
}
if echo "$FILE_INFO" | grep -q "interpreter"; then
    echo "ERROR: sandbox-agent must not reference a dynamic ELF interpreter" >&2
    exit 1
fi
if readelf -l /out/sandbox-agent 2>&1 | grep -q "INTERP"; then
    echo "ERROR: sandbox-agent must not contain a PT_INTERP segment" >&2
    exit 1
fi
if readelf -d /out/sandbox-agent 2>&1 | grep -q "(NEEDED)"; then
    echo "ERROR: sandbox-agent has unexpected shared library dependencies:" >&2
    readelf -d /out/sandbox-agent >&2
    exit 1
fi
ldd /out/sandbox-agent 2>&1 || true

SIZE_BYTES=$(stat -c '%s' /out/sandbox-agent)
echo "sandbox-agent exact size: $SIZE_BYTES bytes (BRD target ~2097152 bytes)"
'@

Invoke-DockerShell `
    -Image "rust:alpine" `
    -MountArgs @("-v", "${RepoRoot}:/src:ro", "-v", "${ResolvedOutDir}:/out") `
    -Script $BuildAgentScript

Write-Host "[2/2] Assembling vmlinuz-virt and initramfs.cpio.gz in alpine:3.20..."
$BuildInitramfsScript = @'
set -eu
apk add --no-cache linux-virt busybox-static kmod gzip file >/dev/null

echo "=== Alpine package pins ==="
apk list -I linux-virt busybox-static

KVER=$(ls /lib/modules | head -n 1)
if [ -z "$KVER" ]; then
    echo "ERROR: no kernel modules directory found under /lib/modules" >&2
    exit 1
fi
echo "Kernel version: $KVER"

cp /boot/vmlinuz-virt /out/vmlinuz-virt
chmod 0644 /out/vmlinuz-virt

ROOTFS="/tmp/initramfs"
rm -rf "$ROOTFS"
mkdir -p \
    "$ROOTFS/bin" \
    "$ROOTFS/sbin" \
    "$ROOTFS/usr/bin" \
    "$ROOTFS/usr/sbin" \
    "$ROOTFS/dev" \
    "$ROOTFS/dev/virtio-ports" \
    "$ROOTFS/proc" \
    "$ROOTFS/sys" \
    "$ROOTFS/tmp" \
    "$ROOTFS/root" \
    "$ROOTFS/etc" \
    "$ROOTFS/lib/modules/$KVER"

cp /bin/busybox.static "$ROOTFS/bin/busybox"
chmod 0755 "$ROOTFS/bin/busybox"
chroot "$ROOTFS" /bin/busybox --install -s

for applet in /bin/sh /bin/uname /bin/echo /bin/cat /bin/false /bin/true /bin/mountpoint /sbin/poweroff /sbin/modprobe /sbin/mdev; do
    if [ ! -e "$ROOTFS$applet" ]; then
        echo "ERROR: expected busybox applet missing: $applet" >&2
        exit 1
    fi
done

cp /out/sandbox-agent "$ROOTFS/bin/sandbox-agent"
chmod 0755 "$ROOTFS/bin/sandbox-agent"

# Include kernel module metadata plus virtio/vsock/char/block modules so modprobe works cleanly
# regardless of whether virtio_console or virtio_pci is modular or builtin.
cp /lib/modules/"$KVER"/modules.* "$ROOTFS/lib/modules/$KVER/"
(
    cd "/lib/modules/$KVER"
    for dir in kernel/drivers/virtio kernel/drivers/char kernel/drivers/block kernel/net/vmw_vsock; do
        [ -d "$dir" ] || continue
        find "$dir" -type f \( -name '*.ko' -o -name '*.ko.*' \) | while IFS= read -r mod; do
            mkdir -p "$ROOTFS/lib/modules/$KVER/$(dirname "$mod")"
            cp "$mod" "$ROOTFS/lib/modules/$KVER/$mod"
        done
    done
)
depmod -b "$ROOTFS" "$KVER"

cat <<'EOF' > "$ROOTFS/etc/passwd"
root:x:0:0:root:/root:/bin/sh
EOF
cat <<'EOF' > "$ROOTFS/etc/group"
root:x:0:
EOF

cat <<'EOF' > "$ROOTFS/init"
#!/bin/sh
export PATH=/bin:/sbin:/usr/bin:/usr/sbin

mountpoint -q /proc || mount -t proc proc /proc
mountpoint -q /sys || mount -t sysfs sysfs /sys
mountpoint -q /dev || mount -t devtmpfs devtmpfs /dev

for mod in virtio virtio_ring virtio_pci_modern_dev virtio_pci_legacy_dev virtio_pci virtio_console vmw_vsock_virtio_transport; do
    modprobe -q "$mod" 2>/dev/null || true
done

mkdir -p /dev/virtio-ports
mdev -s

for port in /sys/class/virtio-ports/*; do
    [ -e "$port/name" ] || continue
    devname=$(basename "$port")
    portname=$(cat "$port/name")
    if [ -n "$portname" ] && [ -e "/dev/$devname" ]; then
        ln -sf "/dev/$devname" "/dev/virtio-ports/$portname"
    fi
done

/bin/sandbox-agent
rc=$?
echo "[init] sandbox-agent exited with code $rc; powering off"
/sbin/poweroff -f
EOF
chmod 0755 "$ROOTFS/init"

# Verify initramfs root runs static sh without any shared libraries and /init is LF-clean.
if grep -q "$(printf '\r')" "$ROOTFS/init"; then
    echo "ERROR: /init contains CR bytes" >&2
    exit 1
fi
chroot "$ROOTFS" /bin/sh -c 'test -x /init && test -x /bin/sandbox-agent'

# Normalize timestamps and ownership for reproducible initramfs output.
find "$ROOTFS" -exec touch -h -d "2026-01-01 00:00:00" {} +
(
    cd "$ROOTFS"
    find . | LC_ALL=C sort | cpio -o -H newc -R 0:0 | gzip -n -9 > /out/initramfs.cpio.gz
)
chmod 0644 /out/initramfs.cpio.gz

echo "=== Guest artifact summary ==="
ls -lh /out/sandbox-agent /out/vmlinuz-virt /out/initramfs.cpio.gz
sha256sum /out/sandbox-agent /out/vmlinuz-virt /out/initramfs.cpio.gz
echo "initramfs entry count: $(zcat /out/initramfs.cpio.gz | cpio -t 2>/dev/null | wc -l)"
'@

Invoke-DockerShell `
    -Image "alpine:3.20" `
    -MountArgs @("-v", "${ResolvedOutDir}:/out") `
    -Script $BuildInitramfsScript

Write-Host ""
Write-Host "Spike guest build complete:"
Get-ChildItem -Path $ResolvedOutDir | Select-Object Name, Length | Format-Table -AutoSize
