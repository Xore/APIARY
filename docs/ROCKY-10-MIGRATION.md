# Rocky Linux 10 support in `install-homeserver.sh`

The homeserver is moving from Ubuntu to Rocky Linux 10. `scripts/install-homeserver.sh`
now runs on both, so the reinstall smoke test in #1609 has a working installer.

## How it works

Every package operation goes through a shim rather than calling `apt-get`
directly:

| helper | Ubuntu/Debian | Rocky/RHEL |
|---|---|---|
| `pkg_update` | `apt-get update -y` | `dnf -y makecache` |
| `pkg_install` | `apt-get install -y --no-install-recommends` | `dnf install -y` |

`$DISTRO_FAMILY` (`debian` or `rhel`) is resolved **once**, at source time, from
`/etc/os-release` — `ID` first, falling back to `ID_LIKE` so derivatives
(AlmaLinux, Mint) land in the right family. Resolving it once means no step can
disagree with what preflight decided.

Only genuinely distro-specific things branch on it. Docker, WireGuard, libvirt
and the whole APIARY provisioning flow are identical once packages are on disk.

## Package name differences

| Ubuntu | Rocky | note |
|---|---|---|
| `dnsutils` | `bind-utils` | `dig`, `nslookup` |
| `gnupg` | `gnupg2` | |
| `openssh-client` | `openssh-clients` | note the plural |
| `ufw` | `firewalld` | RHEL's host firewall |
| `lsb-release` | *(dropped)* | Debian-only; `/etc/os-release` carries the same data |
| `wireguard` | `wireguard-tools` | Ubuntu's is a metapackage |
| `sshfs` | `fuse-sshfs` | |
| `qemu-system-x86` | `qemu-kvm` | |
| `libvirt-daemon-system` | `libvirt-daemon-kvm` | |
| `libvirt-clients` | `libvirt-client` | |
| `virtinst` | `virt-install` | |
| `libguestfs-tools` | `guestfs-tools` | |
| `ovmf` | `edk2-ovmf` | UEFI firmware for the Windows sandbox domains |

Docker's own packages (`docker-ce`, `docker-ce-cli`, `containerd.io`,
`docker-buildx-plugin`, `docker-compose-plugin`) keep the same names in both
repos.

## Repositories

**Docker** — the CentOS repofile is written to `/etc/yum.repos.d/` verbatim
rather than added with `dnf config-manager`, whose syntax changed between dnf4
and dnf5. Its `baseurl` interpolates `$releasever`, which on Rocky resolves to
the **major** version (`10`), not the point release. This was checked, because
Docker publishes `centos/10` but no `centos/10.2` — a point-release
`$releasever` would 404 every package.

**NVIDIA driver** — there is no `ubuntu-drivers` equivalent, so the RHEL path is
explicit: EPEL (for `dkms`) + kernel headers matching the *running* kernel, then
NVIDIA's `cuda-rhel10` repo and the `cuda-drivers` meta-package.

It deliberately uses `cuda-drivers` (proprietary) and **not** `nvidia-open`. The
open kernel modules only support Turing and newer. The homeserver holds a Pascal
Quadro P2200 alongside the Ada RTX 4000; the P2200 is meant to be bound to
`vfio-pci` for the Windows sandbox rather than driven by the host, but choosing
the open modules would make it unusable on the host if ever needed.

**NVIDIA container toolkit** — same rpm repofile approach. On RHEL the
`container_use_devices` SELinux boolean is also set, without which a container
cannot open the GPU device nodes.

## Two things Rocky does that Ubuntu did not

`step_preflight_rhel_platform` **reports** these and does not change them —
turning off a firewall or SELinux is an operator's decision, not something an
installer should do quietly. The step is non-fatal.

**SELinux is enforcing.** The Compose bind mounts were written for Ubuntu and
carry no `:z`/`:Z` labels, so containers can fail with permission denied on
paths under `/var/dockge/stacks`. After the run, check container health and
`ausearch -m avc -ts recent`.

**firewalld is active.** The Ubuntu build installed `ufw` but never enabled it,
so the host previously ran with no firewall at all. Confirm the sensor ports are
reachable from outside before calling the install good.

Both are the most likely causes of a smoke test that "completes" but leaves a
half-working stack — check them first.

## Still Ubuntu-only

`docs/autoinstall/homeserver-user-data.yaml` is a cloud-init/subiquity
autoinstall file. Rocky uses **kickstart**, so the unattended *base OS* install
is a separate artifact that does not carry over. This script covers everything
after the base OS is installed; the base install is manual (or kickstart) for
now.

## Verifying on a Rocky host

```bash
sudo ./scripts/install-homeserver.sh --config /path/to/answers.conf
```

Preflight prints the detected OS and family. If it reports `unknown`, the
distro is unsupported and the run stops there rather than part-way through.
