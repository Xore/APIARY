# Comparing Snapshots vs Golden Images for Rapid Malware Testing

> **Environment:** KVM host (not a nested hypervisor). All commands target
> `libvirt` / `virsh` running directly on the bare-metal KVM host.

---

## Table of Contents

1. [Concepts](#1-concepts)
2. [Comparison at a Glance](#2-comparison-at-a-glance)
3. [KVM Internal Snapshots](#3-kvm-internal-snapshots)
4. [KVM External Snapshots](#4-kvm-external-snapshots)
5. [Golden Images with qcow2 Backing Files](#5-golden-images-with-qcow2-backing-files)
6. [Decision Guide](#6-decision-guide)
7. [Recommended Workflow for This Stack](#7-recommended-workflow-for-this-stack)
8. [Automation Scripts](#8-automation-scripts)
9. [Network Isolation](#9-network-isolation)
10. [Hardening the KVM Host](#10-hardening-the-kvm-host)
11. [Pitfalls & Known Issues](#11-pitfalls--known-issues)

---

## 1. Concepts

### Snapshot
A **snapshot** captures the complete state of a running (or stopped) VM at a
point in time — disk, memory, and device state. Reverting returns the guest to
that exact moment. Libvirt supports two snapshot types:

| Type | Storage | Memory | Live revert? |
|------|---------|--------|-------------|
| **Internal** | Inside the qcow2 image | Optional | ✅ `virsh snapshot-revert` |
| **External** | Separate overlay `.qcow2` | Separate file | ⚠️ Manual XML edit required |

### Golden Image
A **golden image** is a read-only, fully configured base disk that is **never
booted directly**. Every analysis VM is a thin `qcow2` overlay on top of it.
After each malware run the overlay is deleted and a fresh one is created in
seconds — the golden image itself is never touched.

---

## 2. Comparison at a Glance

| Dimension | Internal Snapshot | External Snapshot | Golden Image + Overlay |
|-----------|------------------|------------------|------------------------|
| **Reset speed** | ~5 s (revert) | ~15 s (manual) | ~2 s (delete + recreate overlay) |
| **Disk overhead** | Grows inside qcow2 | Separate chain file | Only overlay grows; base is static |
| **Concurrent VMs** | 1 per snapshot | 1 per snapshot chain | ✅ N VMs share one base |
| **Libvirt revert support** | ✅ Full | ⚠️ Partial (no GUI) | N/A — just recreate |
| **Memory capture** | Optional, in-image | Separate file | Not captured (disk only) |
| **Snapshot chains** | Supported | Supported | Not applicable |
| **Best for** | Ad-hoc testing | Long chain analysis | High-throughput / automated |
| **Risk of corruption** | Medium (grows large) | Low | Very low (base immutable) |

---

## 3. KVM Internal Snapshots

Internal snapshots store delta data inside the qcow2 image itself. They require
the disk format to be `qcow2` (not `raw`).

### 3.1 Prerequisites

```bash
# Verify disk format
virsh domblkinfo <vm-name> vda
qemu-img info /var/lib/libvirt/images/<vm-name>.qcow2 | grep 'file format'
```

### 3.2 Create a Clean Snapshot

```bash
# VM can be running (live) or shut off
virsh snapshot-create-as <vm-name> \
  --name "clean-baseline" \
  --description "Pre-infection clean state" \
  --atomic
```

`--atomic` ensures the snapshot is consistent or not taken at all.

### 3.3 List Snapshots

```bash
virsh snapshot-list <vm-name> --tree
```

### 3.4 Revert After a Malware Run

```bash
# Destroy (force-stop) the infected VM, then revert
virsh destroy <vm-name>
virsh snapshot-revert <vm-name> clean-baseline
virsh start <vm-name>
```

Or in one line for scripting:
```bash
virsh destroy <vm-name> 2>/dev/null; \
virsh snapshot-revert <vm-name> clean-baseline --running
```

`--running` starts the VM automatically after revert.

### 3.5 Delete Old Snapshots

Internal snapshots accumulate and bloat the qcow2 file. Prune regularly:

```bash
# Delete a single snapshot
virsh snapshot-delete <vm-name> <snapshot-name>

# Compact after deletion
qemu-img check -r all /var/lib/libvirt/images/<vm-name>.qcow2
virt-sparsify --in-place /var/lib/libvirt/images/<vm-name>.qcow2
```

---

## 4. KVM External Snapshots

External snapshots write new data to a separate overlay file, leaving the
original disk untouched. The original becomes a read-only backing file.

> ⚠️ **libvirt does not implement `snapshot-revert` for external snapshots.**
> Reverting requires editing domain XML manually or using the helper script
> in [§8](#8-automation-scripts).

### 4.1 Create an External Snapshot

```bash
virsh snapshot-create-as <vm-name> \
  --name "ext-clean" \
  --disk-only \
  --diskspec vda,snapshot=external,file=/var/lib/libvirt/snapshots/<vm-name>-ext-clean.qcow2 \
  --atomic
```

`--disk-only` skips memory capture (faster, usually sufficient for malware
disk forensics).

### 4.2 Verify the Backing Chain

```bash
qemu-img info --backing-chain \
  /var/lib/libvirt/snapshots/<vm-name>-ext-clean.qcow2
```

### 4.3 Manual Revert (Blockcommit)

```bash
# Stop the VM
virsh destroy <vm-name>

# Commit overlay changes back to base (abandon changes = just switch back)
# Edit the domain XML to point vda back to the base image:
virsh edit <vm-name>
# Change: <source file='/path/to/overlay.qcow2'/>
# To:     <source file='/path/to/original.qcow2'/>

# Delete the dirty overlay
rm /var/lib/libvirt/snapshots/<vm-name>-ext-clean.qcow2

# Start clean
virsh start <vm-name>
```

The helper script `sandbox/reset-vm.sh` automates this — see §8.

---

## 5. Golden Images with qcow2 Backing Files

This is the **recommended approach** for the honeypot-stack when running
multiple concurrent analysis VMs or automated sample ingestion pipelines.

### 5.1 Create the Golden Image

```bash
# 1. Install a clean OS as normal, install tools (Sysmon, strace, tcpdump, etc.)
# 2. Shut down the VM cleanly
virsh shutdown golden-win10
# Wait for shutdown
virsh domstate golden-win10

# 3. Compress and lock the image
qemu-img convert -O qcow2 -c \
  /var/lib/libvirt/images/golden-win10.qcow2 \
  /var/lib/libvirt/golden/golden-win10.qcow2

# 4. Make it read-only so nothing can accidentally modify it
chmod 444 /var/lib/libvirt/golden/golden-win10.qcow2
```

### 5.2 Spawn an Analysis VM from the Golden Image

```bash
#!/bin/bash
# Usage: spawn-analysis-vm.sh <sample-name>
SAMPLE="$1"
GOLDEN="/var/lib/libvirt/golden/golden-win10.qcow2"
OVERLAY="/var/lib/libvirt/overlays/analysis-${SAMPLE}-$(date +%s).qcow2"

# Create thin overlay — takes < 1 second
qemu-img create -f qcow2 -b "$GOLDEN" -F qcow2 "$OVERLAY"

# Clone the domain XML, replace disk path, define and start
virt-clone \
  --original golden-win10 \
  --name    "analysis-${SAMPLE}" \
  --file    "$OVERLAY" \
  --preserve-data   # use the overlay we already created

virsh start "analysis-${SAMPLE}"
echo "VM analysis-${SAMPLE} started with overlay $OVERLAY"
```

### 5.3 Destroy and Clean Up After the Run

```bash
VM="analysis-${SAMPLE}"
OVERLAY=$(virsh domblklist "$VM" | awk '/vda/{print $2}')

virsh destroy  "$VM" 2>/dev/null
virsh undefine "$VM" --remove-all-storage 2>/dev/null || true
rm -f "$OVERLAY"
echo "Cleaned up $VM"
```

Because the golden image is read-only and was never touched, the next
analysis VM spawns in an identical clean state.

### 5.4 Updating the Golden Image

When you need to patch or add tools:

```bash
# Temporarily make writable
chmod 644 /var/lib/libvirt/golden/golden-win10.qcow2

# Boot directly from the golden image (define a temp domain)
virsh define /etc/libvirt/qemu/golden-win10.xml
virsh start golden-win10
# ... apply patches / install tools ...
virsh shutdown golden-win10

# Compress new version
qemu-img convert -O qcow2 -c \
  /var/lib/libvirt/golden/golden-win10.qcow2 \
  /var/lib/libvirt/golden/golden-win10-$(date +%Y%m%d).qcow2

# Lock again
chmod 444 /var/lib/libvirt/golden/golden-win10-$(date +%Y%m%d).qcow2
```

Keep the last 2–3 dated versions for rollback.

---

## 6. Decision Guide

```
Are you running automated / high-volume sample ingestion?
  YES → Golden Image + Overlay  (§5)
  NO  →
    Do you need memory snapshots (unpacking, rootkit analysis)?
      YES → Internal Snapshot with memory (§3)
      NO  →
        Do you need a chain of states (stage1 → stage2 → stage3)?
          YES → External Snapshot chain (§4)
          NO  → Internal Snapshot, disk only (§3) or Golden Image
```

---

## 7. Recommended Workflow for This Stack

The honeypot-stack uses **Cowrie → Dionaea → sample drop** as the capture
pipeline. The recommended VM topology on a KVM host:

```
KVM Host (bare metal)
├── golden/
│   ├── golden-win10.qcow2      (read-only, Windows analysis VM)
│   └── golden-ubuntu22.qcow2   (read-only, Linux ELF analysis VM)
├── overlays/
│   ├── analysis-<hash1>.qcow2  (active run, thin overlay)
│   └── analysis-<hash2>.qcow2  (concurrent run)
└── snapshots/
    └── (internal snapshots for ad-hoc manual testing)
```

### End-to-End Automated Analysis Flow

```
1. Cowrie / Dionaea captures sample → drops to samples/
2. GitHub Action (Honeypot repo) triggers → scanner APIs run
3. Simultaneously: sandbox/reset-vm.sh spawns fresh overlay VM
4. Sample is transferred into the VM via virtio-serial or shared dir
5. VM executes sample; tcpdump + auditd + Sysmon capture all activity
6. After TTL (e.g. 5 min): artifacts collected, overlay VM destroyed
7. Artifacts pushed to analysis/ dir for further processing
```

---

## 8. Automation Scripts

See [`sandbox/reset-vm.sh`](../sandbox/reset-vm.sh) for a ready-to-use
all-in-one helper that handles:

- Destroying a running VM
- Reverting an internal snapshot **or** recreating from golden image
- Starting the clean VM
- Optionally copying a sample into the VM via `virsh qemu-agent-command`

---

## 9. Network Isolation

Malware VMs **must not** reach the internet or the KVM host network.
Recommended libvirt network setup:

```xml
<!-- /etc/libvirt/qemu/networks/malware-isolated.xml -->
<network>
  <name>malware-isolated</name>
  <bridge name="virbr-mal" stp="on" delay="0"/>
  <!-- No <forward> element = fully isolated, no NAT, no routing -->
  <ip address="10.66.0.1" netmask="255.255.255.0">
    <dhcp>
      <range start="10.66.0.2" end="10.66.0.50"/>
    </dhcp>
  </ip>
</network>
```

```bash
# Apply
virsh net-define   /etc/libvirt/qemu/networks/malware-isolated.xml
virsh net-autostart malware-isolated
virsh net-start     malware-isolated
```

To simulate internet for C2 callback analysis, run a **INetSim** or
**FakeNet-NG** instance on the host at `10.66.0.1` — malware sees responses
but no real traffic leaves the host.

```bash
# Install INetSim on the KVM host
apt install inetsim
# Edit /etc/inetsim/inetsim.conf: service_bind_address 10.66.0.1
systemctl start inetsim
```

---

## 10. Hardening the KVM Host

The KVM host itself is the last line of defence. A compromised guest must not
reach the host.

```bash
# 1. Prevent VMs from writing to host paths via virtio-fs
#    (only use virtio-serial for controlled file transfer)

# 2. AppArmor / SELinux
#    Ubuntu: libvirt ships with AppArmor profiles
aa-enforce /etc/apparmor.d/usr.sbin.libvirtd
aa-enforce /etc/apparmor.d/usr.lib.libvirt.virt-aa-helper

# 3. No shared clipboard, no USB passthrough on analysis VMs
#    Ensure the domain XML does NOT contain:
#    <channel type='spicevmc'> or <redirdev bus='usb'>

# 4. Separate storage pool for golden images — different mount point
mkdir -p /mnt/golden
mount /dev/sdX1 /mnt/golden
chown root:root /mnt/golden && chmod 755 /mnt/golden

# 5. Audit QEMU processes
auditctl -w /usr/bin/qemu-system-x86_64 -p x -k kvm_exec

# 6. Limit QEMU resource usage
#    Set <memtune> and <cputune> in domain XML to prevent
#    malware from starving the host.
```

---

## 11. Pitfalls & Known Issues

| Issue | Cause | Fix |
|-------|-------|-----|
| Internal snapshot revert fails with "domain is running" | VM still running | `virsh destroy <vm>` first |
| External snapshot revert not available in `virsh` | libvirt limitation | Use `blockcommit` or the `reset-vm.sh` script |
| qcow2 image grows unboundedly | Snapshots never pruned | Schedule `virt-sparsify` + snapshot cleanup weekly |
| Golden image accidentally modified | booted directly | `chmod 444` on golden; always boot overlays |
| Analysis VM reaches internet | Wrong network | Attach VM to `malware-isolated` network only |
| Concurrent VMs corrupt golden image | Multiple writers | qcow2 backing files are always read-only to guests — safe by design |
| `virt-clone` is slow | Copies full disk | Use `--preserve-data` + pre-created overlay to avoid copy |

---

## References

- [libvirt Snapshots KB](https://libvirt.org/kbase/snapshots.html)
- [libvirt External Snapshot Management](https://wiki.libvirt.org/I_created_an_external_snapshot_but_libvirt_will_not_let_me_delete_or_revert_to_it.html)
- [KVM External Snapshot Revert (SuperUser)](https://superuser.com/questions/1210773/how-do-i-revert-to-latest-external-snapshot-in-kvm)
- [CAPE Sandbox + KVM automation](https://endsec.au/blog/building-an-automated-malware-sandbox-using-cape/)
- [HoneyDOC Architecture (arXiv 2024)](https://arxiv.org/abs/2402.06516)
