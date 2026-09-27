# Host performance tuning (Rocky Linux 10)

`scripts/tune-rocky10.sh` applies five host tunings to a Rocky Linux 10
homeserver. It is idempotent, safe to re-run, and supports `--dry-run`.

```bash
sudo ./scripts/tune-rocky10.sh --dry-run   # show what would change
sudo ./scripts/tune-rocky10.sh             # apply
```

> **Status (2026-09-27): the script is not fully applied on the live homeserver.**
> The host was re-provisioned onto Rocky Linux 10.2 on 2026-09-03, and the
> install it now has differs from the one this script was written against. Read
> the checklist in "Verifying afterwards" as *the intended end state*, not as a
> description of the box — re-measured read-only over `ssh homeserver` on
> 2026-09-27, it currently fails two of its six lines:
>
> - **#1 (zram) is not in effect.** `zram-generator` is not installed, no zram
>   module is loaded, `zramctl` prints nothing, and `swapon --show` lists only
>   the 32G LVM swap. An `/etc/systemd/zram-generator.conf` *does* exist, but it
>   is not the file this script writes: it has no `# Managed by` header and
>   sizes the device with `min(ram / 2, 32768)` rather than the computed MB
>   value the script emits, so it was hand-written — and nothing consumes it
>   while the package is missing.
> - **#2 (scheduler rule) is not in effect.**
>   `/etc/udev/rules.d/60-apiary-ioscheduler.rules` does not exist. The
>   schedulers that *are* set came from elsewhere: `nvme0n1` is on `none` and
>   the 8.7T rotational `sdb` is on `mq-deadline`, but the non-rotational `sda`
>   is also on `none` where this script's rule would put it on `kyber`.
> - **#4 (noatime) is half done.** `/var` carries `noatime` in `/etc/fstab`;
>   `/home`, which is a separate mount on this install and did not exist in
>   `/etc/fstab` before the re-provision, is still `defaults`.
> - **#5 (CPU governor) is in effect** — `tuned-adm active` reports
>   `throughput-performance` and cpu0's governor is `performance`.
>
> The 20 GB figure in the sizing note below is still right: the live
> `NVIDIA RTX 4000 Ada Generation` reports 20475 MiB.

These are the Rocky/RHEL-family equivalents of the tunings, not a
transliteration of the Debian recipe. The differences are the point: the
Debian instructions do not work here, and two of them do not survive a reboot
even on Debian.

| # | Tuning | Debian recipe | What this script does instead, and why |
|---|---|---|---|
| 1 | zram swap | `apt install zram-config` | `zram-config` does not exist on Rocky. Uses `zram-generator` with an explicit `/etc/systemd/zram-generator.conf`. |
| 2 | I/O scheduler | `echo none > /sys/block/.../scheduler` | A sysfs write is lost at reboot. Installs a udev rule so the setting is reapplied on every device add. |
| 3 | Trim boot services | `systemctl disable cups` | Same idea, but only disables a fixed, conservative list and only when actually enabled. Everything else is *reported* via `systemd-analyze blame` for a human to judge. |
| 4 | `noatime` | edit `/etc/fstab` | Same, restricted to data mounts. `/` and `/boot` are never touched, and `/etc/fstab` is backed up before any edit. |
| 5 | CPU governor | `echo performance > .../scaling_governor` | Also lost at reboot, and fights `tuned`, which Rocky runs by default. Sets the `throughput-performance` tuned profile, which pins the governor persistently. |

## Sizing and defaults

**zram** is sized at half of RAM, capped at 8 GB. Compressed pages still live
in real memory, so a larger device competes with the workload it is meant to
help.

**The on-disk swap partition is kept by default**, at a worse priority than
zram (zram is priority 100). This is deliberate. APIARY runs models that spill
out of the 20 GB card into host RAM; zram compresses, but it cannot hold pages
the way a real swap device can, and an OOM part-way through a benchmark sweep
costs the whole run. Pass `--replace-swap` to disable the disk swap instead —
the fstab entry is commented out, not deleted, and fstab is backed up first.

**Schedulers** are assigned by device class: NVMe gets `none` (the drive's own
queues make a software scheduler pure added latency), non-rotational SATA gets
`kyber`, rotational disks keep `mq-deadline`.

## What it does not do

It does not partition, reformat, or delete data, and it does not touch `/` or
`/boot` in `/etc/fstab`. Service disabling is limited to printing, Bluetooth
and the modem manager — the only daemons safe to assume a headless server does
not need.

## Verifying afterwards

```bash
zramctl                                   # zram0 present, zstd
swapon --show                             # zram0 at a better priority than any disk swap
cat /sys/block/nvme0n1/queue/scheduler    # [none]
findmnt -no OPTIONS /var                # contains noatime
tuned-adm active                          # throughput-performance
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
```

`noatime` changes in `/etc/fstab` take effect on remount or reboot, not
immediately.
