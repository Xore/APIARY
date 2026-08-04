# Homeserver disk layout and reproducible install

This documents the physical disk layout of the honeypot homeserver
(`supermicro`) as it actually exists today, and a generated Ubuntu
**autoinstall** config (the Ubuntu/subiquity equivalent of Windows'
`autounattend.xml`) to reproduce that layout on a reinstall or a second
build server. Captured 2026-08-04 as part of the #518 smoke-test research.

Ubuntu Server's installer (`subiquity`) is driven by `curtin` under the
hood — the fstab comments on this box literally say "was on /dev/sdX
during curtin installation", confirming this machine was already installed
this way rather than by hand.

## Why this layout, not one big disk

The OS disk (NVMe) is deliberately small and separate from the bulk
storage disks. Docker/Dockge state, container images, and honeypot capture
data are heavy-churn and can grow unpredictably (payload captures, ELK
indices, sandbox images) — keeping them off the boot disk means a runaway
log or a bad `docker system df` can't take the OS down with it, and a
reinstall of the OS disk alone doesn't touch captured evidence.

## Physical layout (as installed)

| Device | Model | Size | Partition table | Filesystem | Mount | Role |
|---|---|---|---|---|---|---|
| `nvme0n1` | Samsung MZVLW256HEHP | 238.5G | GPT | vfat (p1) / ext4 (p2) | `/boot/efi`, `/` | OS + EFI, boot disk |
| `sdb` | AVAGO MR9440-8i (RAID LUN) | 1.7T | whole-disk (no partition table) | xfs | `/var` | Docker root, Dockge stacks, container state — this is where `/var/lib/docker` and `/var/dockge` actually live |
| `sdc` | AVAGO MR9440-8i (RAID LUN) | 1.7T | GPT, 1 partition | xfs | `/mnt-1` | Secondary bulk storage (in use: `github` checkouts) |
| `sda` | Intel SSDSC2KB480G8L | 447.1G | GPT, 1 partition | xfs | `/mnt-2` | Reserved bulk storage (currently empty) |
| `sr0` | ATAPI optical | — | — | — | — | Unused |

Two of the three non-boot disks (`sdb`, `sdc`) sit behind an AVAGO/LSI
MR9440-8i hardware RAID controller and appear to the OS as SCSI LUNs, not
raw disks — the controller's own RAID/cache configuration (level, write
policy, battery/flash backup) is out of band from this OS-level view and
needs to be captured separately from the controller's own tooling
(`storcli`/`perccli` or vendor equivalent) if the RAID config itself needs
to be reproducible, not just the OS partitioning on top of it.

`/var` on its own disk is the key decision: `/var/lib/docker` is 103G and
`/var/dockge` (bind-mounted stack data for all 23 Dockge stacks, including
Elasticsearch indices, Cowrie logs, payload captures, sandbox disks) is
229G — 332G combined, well past what the 238G OS disk could hold even
before accounting for the OS itself. Putting `/var` on the 1.7T `sdb`
disk instead of growing the root filesystem was the right call and should
be preserved on any rebuild.

Swap is an **8G swapfile** at `/swap.img` on the root filesystem, not a
dedicated partition — simpler to resize than a swap partition and fine at
this scale (91G RAM, swap is a safety margin not a working set).

## Reproducing it: `autoinstall/homeserver-user-data.yaml`

The autoinstall config in
[`docs/autoinstall/homeserver-user-data.yaml`](autoinstall/homeserver-user-data.yaml)
reproduces the disk layout above using `curtin`'s storage config directly
(the same declarative format subiquity itself generates — more precise
and reviewable than driving the TUI). Boot an Ubuntu Server 24.04+ ISO with
`autoinstall` on the kernel command line (or bake it into a custom ISO)
pointing at this file, e.g. served over HTTP:

```
# on the install media's GRUB/boot prompt:
autoinstall ds=nocloud-net;s=http://<your-http-server>/autoinstall/
```

with `homeserver-user-data.yaml` renamed to `user-data` alongside an empty
`meta-data` file at that URL path, per Ubuntu's
[autoinstall quick-start](https://canonical-subiquity.readthedocs-hosted.com/en/latest/tutorial/providing-autoinstall.html).

**What the template captures:**
- 4-disk layout above, matched by disk size range rather than
  `/dev/sdX` device names (device letters aren't stable across boots or
  hardware swaps — matching by size is more portable than hardcoding
  `/dev/nvme0n1` etc., though you should still confirm the `match` blocks
  against `lsblk -d -o NAME,SIZE,TRAN` on the target hardware before
  trusting an unattended run).
- GPT + EFI on the boot disk, ext4 root, no LVM (matches what's installed
  today — this box does not use LVM).
- `/var` as its own whole-disk xfs filesystem, `/mnt-1` and `/mnt-2` as
  GPT+xfs single-partition disks.
- 8G swapfile instead of a swap partition.
- Static hostname `supermicro`, `Europe/Berlin` timezone, matching the
  live box — **change both** for a second/different build server; don't
  copy this file byte-for-byte onto new hardware without editing the
  identity fields marked `# CHANGE ME` in the template.
- Network config is deliberately left as DHCP-on-all-NICs in the
  template, not copied from the live box's netplan (which pins interfaces
  by MAC address and sets up a metric-based dual-uplink — that's specific
  to this box's NICs and the WireGuard-uplink setup documented in
  `docs/CGNAT-DEPLOYMENT.md`, and shouldn't be blindly reproduced on
  different hardware).
- Does **not** attempt to reproduce the AVAGO RAID controller's own LUN
  configuration — that has to happen before the OS installer ever sees a
  block device, via the controller's own boot-time utility or `storcli`.
  Document that separately if/when a bare-metal rebuild is actually
  planned (out of scope for this pass — see open question in
  [`docs/research/518-smoke-test-research.md`](research/518-smoke-test-research.md)).

**What's intentionally not templated:** GPU driver install, Docker/
Dockge install, NVIDIA container toolkit, WireGuard, and all the honeypot
stack deployment — those are post-install configuration management, not
disk partitioning, and belong in the single install script that #518 is
building, not in the autoinstall `user-data`. Ubuntu autoinstall supports
a `late-commands`/`user-data` cloud-init hook to chain into a
provisioning script automatically after first boot; once the install
script from #518 exists, wire it in there rather than growing this
YAML file into a general-purpose provisioner.

## VPS: no equivalent template

The VPS (`87.106.162.235`) is a single 120G virtio disk (`vda`), plain GPT
with root/boot/ESP partitions, no RAID, no extra mounts — it was
provisioned from the hosting provider's stock image, not PXE/ISO
autoinstall, so there's no autoinstall config to generate for it. If the
provider supports cloud-init user-data at instance-creation time, that's
the equivalent mechanism worth documenting once someone confirms which
provider workflow was actually used to create this instance — not
guessed at here.
