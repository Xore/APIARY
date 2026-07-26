# Automating Golden Image Creation with Packer and QEMU
## Implementation Guide for KVM Host (honeypot-stack)

> **Host**: KVM + QEMU + libvirt + docker-compose (no VMware, no Hyper-V)  
> **Goal**: Fully automated, reproducible Windows 11 golden image as a `qcow2` file  
> **Reference**: [proactivelabs/packer-windows](https://github.com/proactivelabs/packer-windows), [actuated.com Packer+QEMU guide](https://actuated.com/blog/automate-packer-qemu-image-builds)

---

## Why Packer + QEMU?

Manually building a Windows analysis VM is a multi-hour, error-prone process:
you click through installers, run scripts, reboot several times, and end up
with a VM you can never exactly reproduce. If it gets corrupted or drift
occurs over months, you start over from scratch.

**Packer** solves this by codifying the entire build as version-controlled HCL.
Every golden image build is:
- Identical (same tools, same config, same registry state)
- Auditable (git history shows every change)
- Automatable (CI can rebuild on schedule or when tooling changes)
- Shareable (qcow2 can be moved to any KVM host)

On a KVM host, Packer uses the **QEMU builder** with `accelerator = "kvm"`,
which gives near-native performance via hardware virtualisation.

---

## Architecture: How Packer Builds the Image

```
KVM Host
  │
  ├── packer build win11-analysis.pkr.hcl
  │     │
  │     ├── 1. QEMU boots Windows 11 ISO with KVM acceleration
  │     ├── 2. autounattend.xml on floppy → fully unattended install
  │     ├── 3. WinRM auto-enabled via FirstLogonCommands
  │     ├── 4. Packer connects via WinRM → runs PowerShell provisioners
  │     ├── 5. setup_analysis.ps1: Chocolatey → FLARE-VM → Sysmon →
  │     │                        PS logging → FakeNet-NG → hardening
  │     └── 6. Shutdown → export win11-analysis.qcow2
  │
  └── /golden-images/win11-analysis.qcow2  (~30 GB)
        │
        ├── qemu-img create (thin clone) → /vms/win11-sandbox.qcow2
        ├── virsh define → VM defined in libvirt
        └── virsh snapshot-create-as GOLDEN_READY
              │
              └── virsh snapshot-revert GOLDEN_READY  (before each run, 5-10s)
```

---

## Step 0: Host Prerequisites

### 0.1 Verify KVM is available

```bash
# Check hardware virtualisation support
egrep -c '(vmx|svm)' /proc/cpuinfo
# Must return > 0. If 0: enable VT-x/AMD-V in BIOS.

# Check KVM module loaded
lsmod | grep kvm
# Expected: kvm_intel (or kvm_amd) + kvm

# Quick sanity check
kvm-ok
# Should print: INFO: /dev/kvm exists  KVM acceleration can be used
```

### 0.2 Install required packages

```bash
sudo apt update
sudo apt install -y \
    qemu-kvm \
    qemu-utils \
    libvirt-daemon-system \
    libvirt-clients \
    virtinst \
    bridge-utils \
    genisoimage \
    ovmf \
    python3-libvirt

# Add your user to kvm + libvirt groups (requires logout/login)
sudo usermod -aG kvm,libvirt $USER

# Verify
virsh --version   # should print e.g. 8.0.0
qemu-img --version
```

### 0.3 Install Packer

```bash
# HashiCorp apt repo
curl -fsSL https://apt.releases.hashicorp.com/gpg \
  | gpg --dearmor -o /usr/share/keyrings/hashicorp.gpg

echo "deb [signed-by=/usr/share/keyrings/hashicorp.gpg] \
https://apt.releases.hashicorp.com $(lsb_release -cs) main" \
  | sudo tee /etc/apt/sources.list.d/hashicorp.list

sudo apt update && sudo apt install -y packer

# Verify
packer version   # should print 1.10.x or later

# Install QEMU plugin
packer plugins install github.com/hashicorp/qemu
```

### 0.4 Install OVMF (UEFI firmware for Windows 11)

Windows 11 requires UEFI + TPM. On KVM we use OVMF and bypass TPM via
`autounattend.xml` registry keys.

```bash
sudo apt install -y ovmf

# Verify firmware files exist
ls /usr/share/OVMF/
# Should include: OVMF_CODE_4M.secboot.fd, OVMF_VARS_4M.ms.fd
# If not found, try: /usr/share/qemu/OVMF.fd (path varies by distro)
```

### 0.5 Prepare image directories

```bash
sudo mkdir -p /golden-images /vms /isos
sudo chown $USER:$USER /golden-images /vms
```

---

## Step 1: Get the Windows 11 ISO

### Option A: Windows 11 Enterprise Evaluation (recommended, free 90 days)

```
https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise
```

Download the **ISO** (not the VHD). Place at:
```bash
mv ~/Downloads/WIN11_ENT_EVAL*.ISO /isos/Win11_Eval_x64.iso
```

### Option B: Windows 11 Consumer ISO via Media Creation Tool

Run on a Windows machine, create ISO. No product key needed for 30-day trial.

### Get the ISO checksum

```bash
sha256sum /isos/Win11_Eval_x64.iso
# Copy output hash — put it in win11-analysis.pkr.hcl as iso_checksum
```

---

## Step 2: Understand the Packer Build File

File: [`sandbox/windows/packer/win11-analysis.pkr.hcl`](../packer/win11-analysis.pkr.hcl)

### Key sections explained

#### QEMU source block

```hcl
source "qemu" "win11" {
  accelerator      = "kvm"          # Hardware acceleration via KVM
  machine_type     = "q35"          # Modern PCIe chipset (required for UEFI)
  efi_boot         = true           # UEFI required for Windows 11
  cpu_model        = "host"         # Pass-through real CPU — anti-sandbox-detection
  disk_interface   = "virtio"       # Fast paravirtual disk
  net_device       = "e1000e"       # Intel NIC model — looks like real hardware
  floppy_files     = ["autounattend.xml"]  # Unattended install answer file
  communicator     = "winrm"        # Packer connects via WinRM after install
  winrm_timeout    = "6h"           # FLARE-VM takes 2-4 hours
  headless         = true           # No GUI window on KVM host
}
```

#### Why `machine_type = "q35"`?

Q35 is a modern Intel PCIe chipset emulation. It supports:
- PCIe bus (required for NVME/virtio-blk)
- AHCI (SATA, more realistic than IDE)
- IOMMU
- UEFI SecureBoot

Windows 11 checks for a modern chipset. Q35 passes this check; the old
`pc` (i440fx) does not.

#### Why `cpu_model = "host"`?

With `cpu_model = "host"` (pass-through), the guest Windows VM sees the
exact CPU model of the physical host (e.g. Intel Core i9-13900K). Without
this, QEMU presents a generic `qemu64` CPU — easily detected by malware
that checks CPUID. This is critical for anti-sandbox-detection.

#### Why `net_device = "e1000e"`?

`e1000e` emulates an Intel 82574L Gigabit NIC — one of the most common
NICs in real desktop hardware. The alternative (`virtio-net`) has QEMU
strings in its driver and is easily detected by sandbox-aware malware.

---

## Step 3: Understand the autounattend.xml

File: [`sandbox/windows/packer/autounattend.xml`](../packer/autounattend.xml)

This XML file is the Windows unattended installation answer file. Packer
passes it via a virtual floppy disk (`A:\autounattend.xml`). Windows Setup
reads it automatically on boot.

### Key elements

#### TPM/SecureBoot bypass (critical for KVM)

```xml
<RunSynchronousCommand>
  <Path>reg add HKLM\SYSTEM\Setup\LabConfig /v BypassTPMCheck /t REG_DWORD /d 1 /f</Path>
</RunSynchronousCommand>
<RunSynchronousCommand>
  <Path>reg add HKLM\SYSTEM\Setup\LabConfig /v BypassSecureBootCheck /t REG_DWORD /d 1 /f</Path>
</RunSynchronousCommand>
```

Windows 11 requires TPM 2.0 and SecureBoot. KVM/QEMU can emulate a virtual
TPM (`swtpm`) but it's complex. The `LabConfig` registry keys are the official
Microsoft method to bypass these checks in lab/evaluation environments.

#### UEFI partition layout

```xml
<CreatePartition>
  <Type>EFI</Type><Size>260</Size>    <!-- EFI System Partition -->
</CreatePartition>
<CreatePartition>
  <Type>MSR</Type><Size>16</Size>     <!-- Microsoft Reserved -->
</CreatePartition>
<CreatePartition>
  <Type>Primary</Type><Extend>true</Extend>  <!-- Windows -->
</CreatePartition>
```

This creates the standard Windows 11 GPT partition layout. BIOS/MBR will
not work with Windows 11.

#### WinRM enablement (how Packer connects)

```xml
<FirstLogonCommands>
  <SynchronousCommand>
    <CommandLine>cmd /c winrm quickconfig -q</CommandLine>
  </SynchronousCommand>
  <SynchronousCommand>
    <CommandLine>cmd /c winrm set winrm/config/service @{AllowUnencrypted="true"}</CommandLine>
  </SynchronousCommand>
</FirstLogonCommands>
```

Packer connects to the Windows VM via WinRM (Windows Remote Management)
over port 5985. The `FirstLogonCommands` enable WinRM before the first
login completes, so Packer can start running provisioners immediately.

---

## Step 4: The Provisioner Script

File: [`sandbox/windows/packer/scripts/setup_analysis.ps1`](../packer/scripts/setup_analysis.ps1)

This runs inside the Windows VM via WinRM during the Packer build.
It has 14 sequential phases:

| Phase | Action | Notes |
|-------|--------|-------|
| 1 | Network config | Real DNS during build (Chocolatey needs internet), INetSim DNS set at end |
| 2 | Disable Defender | Real-time, cloud, MAPS, sample submission |
| 3 | Disable Windows Update | Service + GPO |
| 4 | Disable Telemetry | `DiagTrack`, `dmwappushservice`, registry |
| 5 | Disable UAC | Required for unattended tool installs |
| 6 | Disable Firewall | FakeNet-NG handles all traffic |
| 7 | Disable SmartScreen | Prevents blocking of malware samples |
| 8 | Install Chocolatey | Package manager for FLARE-VM |
| 9 | Install FLARE-VM | 100+ analysis tools, takes 2-4 hours |
| 10 | Install Sysmon | With SwiftOnSecurity config |
| 11 | PowerShell logging | ScriptBlock (4104), Module (4103), Transcription |
| 12 | Process auditing | Event 4688 with full command line |
| 13 | Install FakeNet-NG | Network interception on guest |
| 14 | Install QEMU Guest Agent | Enables host-side file copy via guest agent |
| 15 | Decoy environment | Fake documents, browser history, recent files |
| 16 | Set DNS to INetSim | Final step: all DNS → 10.10.10.1 |

### Important: Internet Access During Build

During the Packer build, the QEMU VM needs **real internet access** to
download Chocolatey, FLARE-VM packages, Sysmon, etc. This is handled by:

1. Packer's default QEMU networking uses **user-mode networking (SLIRP)**
   which provides NAT internet access through the host.
2. DNS is temporarily set to `8.8.8.8` during the build.
3. At the very last step, DNS is set to `10.10.10.1` (INetSim) for analysis.

The final golden image has no internet access once deployed onto the
isolated `virbr-sandbox` network.

---

## Step 5: Run the Packer Build

```bash
cd sandbox/windows/packer

# 1. Update the ISO checksum in the HCL file
SHA=$(sha256sum /isos/Win11_Eval_x64.iso | cut -d' ' -f1)
sed -i "s|none:skip|sha256:${SHA}|" win11-analysis.pkr.hcl

# 2. Update the ISO path if different
sed -i 's|/isos/Win11_Eval_x64.iso|/isos/YOUR_ISO_NAME.iso|' win11-analysis.pkr.hcl

# 3. Initialise Packer plugins
packer init win11-analysis.pkr.hcl

# 4. Validate the template
packer validate win11-analysis.pkr.hcl

# 5. Build (takes 3-5 hours)
# /dev/kvm must be accessible
sudo chmod o+rw /dev/kvm   # or add user to kvm group and re-login

packer build win11-analysis.pkr.hcl

# Output:
#   /golden-images/win11-analysis.qcow2   (~30 GB)
```

### Build with debug output (for troubleshooting)

```bash
# See all WinRM output and Packer steps
PACKER_LOG=1 packer build win11-analysis.pkr.hcl 2>&1 | tee /tmp/packer_build.log

# Run with GUI window visible (disable headless for debugging)
packer build -var='headless=false' win11-analysis.pkr.hcl
# Note: requires a display or X11 forwarding on the KVM host
```

### Expected build timeline

| Stage | Duration |
|-------|----------|
| Windows 11 installation | ~30-45 min |
| First boot + WinRM ready | ~10 min |
| Chocolatey install | ~5 min |
| FLARE-VM install | ~2-4 hours |
| Sysmon + logging config | ~5 min |
| FakeNet-NG + cleanup | ~5 min |
| **Total** | **~3-5 hours** |

---

## Step 6: Create the VM from the Golden Image

```bash
# Thin-clone from golden image using Copy-on-Write
# The clone disk starts at ~0 bytes extra, grows only as changes are written
qemu-img create -f qcow2 -F qcow2 \
    -b /golden-images/win11-analysis.qcow2 \
    /vms/win11-sandbox.qcow2

# Verify
qemu-img info /vms/win11-sandbox.qcow2
# Should show: backing file: /golden-images/win11-analysis.qcow2
```

### Define the VM in libvirt

Use the helper script:
```bash
chmod +x sandbox/windows/setup/kvm_manage.sh
sandbox/windows/setup/kvm_manage.sh create
```

Or manually with `virt-install`:
```bash
virt-install \
  --name win11-sandbox \
  --memory 8192 \
  --vcpus 4 \
  --cpu host \
  --disk path=/vms/win11-sandbox.qcow2,bus=virtio,cache=none \
  --network network=sandbox,model=e1000e \
  --os-variant win11 \
  --boot uefi \
  --graphics none \
  --import \
  --noautoconsole
```

### Take the GOLDEN_READY snapshot

```bash
# Start VM once to verify it boots
virsh start win11-sandbox
# Wait ~60s for boot

# Verify WinRM is responsive
python3 -c "
import winrm, os
s = winrm.Session('10.10.10.2', auth=('analyst', 'malware123!'), transport='ntlm')
print(s.run_ps('Write-Output ready').std_out)
"

# Take snapshot while running
virsh snapshot-create-as win11-sandbox GOLDEN_READY \
    --description "FLARE-VM + Sysmon + FakeNet-NG + PS logging" \
    --atomic

# Verify
virsh snapshot-list win11-sandbox
```

---

## Step 7: Snapshot Workflow for Analysis Runs

### Before every detonation run

```bash
# Revert to clean golden state (~5-10 seconds)
virsh snapshot-revert win11-sandbox GOLDEN_READY --running

# Wait for WinRM
sleep 60

# Run your sample
python3 sandbox/windows/orchestrate/run_sample.py --sample samples/PE/evil.exe
```

### After every run (handled automatically by run_sample.py)

```bash
# Always revert regardless of success/failure
virsh snapshot-revert win11-sandbox GOLDEN_READY --running
```

---

## Step 8: Rebuilding and Updating the Golden Image

### Full rebuild (e.g. FLARE-VM update, quarterly refresh)

```bash
# Remove old VM + snapshot first
virsh destroy win11-sandbox 2>/dev/null || true
virsh snapshot-delete win11-sandbox GOLDEN_READY 2>/dev/null || true
virsh undefine win11-sandbox --nvram
rm /vms/win11-sandbox.qcow2

# Rebuild golden image from scratch
packer build -force sandbox/windows/packer/win11-analysis.pkr.hcl

# Recreate VM + snapshot
sandbox/windows/setup/kvm_manage.sh create
sandbox/windows/setup/kvm_manage.sh snapshot
```

### Quick config patch (no full rebuild needed)

Use `virt-customize` from `libguestfs-tools` to patch the qcow2 offline:

```bash
sudo apt install libguestfs-tools

# Update Sysmon config without rebuilding
virt-customize -a /golden-images/win11-analysis.qcow2 \
    --upload sandbox/windows/config/sysmon_config.xml:/Windows/sysmon_config.xml \
    --run-command 'C:\\Windows\\Sysmon64.exe -c C:\\Windows\\sysmon_config.xml'

# Update FakeNet config
virt-customize -a /golden-images/win11-analysis.qcow2 \
    --upload sandbox/windows/config/fakenet.ini:/Tools/FakeNet/configs/honeypot_fakenet.ini

# After patching qcow2, recreate the thin-clone and snapshot
rm /vms/win11-sandbox.qcow2
sandbox/windows/setup/kvm_manage.sh create
sandbox/windows/setup/kvm_manage.sh snapshot
```

---

## Step 9: KVM-Specific Anti-Detection Settings

Applied in the VM XML (`packer/win11-kvm.xml`). These make the guest look
like real hardware, not a QEMU VM:

```xml
<!-- Hide KVM from guest CPUID — most important -->
<features>
  <kvm><hidden state='on'/></kvm>
  <vmport state='off'/>   <!-- disable VMware I/O port check (some malware checks both) -->
</features>

<!-- CPU: host pass-through, guest sees real CPU model -->
<cpu mode='host-passthrough'>
  <feature policy='disable' name='hypervisor'/>  <!-- hide hypervisor CPUID bit -->
</cpu>

<!-- Disk: custom serial number resembling real HDD -->
<disk type='file' device='disk'>
  <driver name='qemu' type='qcow2' cache='none'/>
  <serial>WD-WX31A74K3593</serial>
</disk>

<!-- NIC: Intel e1000e with real Intel OUI MAC prefix -->
<interface type='network'>
  <mac address='00:1A:2B:3C:4D:5E'/>
  <model type='e1000e'/>
</interface>
```

### Why each setting matters

| Setting | What malware checks | Without it |
|---------|---------------------|------------|
| `kvm hidden` | CPUID leaf 0x40000000 for KVM signature | Malware detects KVM via CPUID |
| `vmport off` | VMware backdoor I/O port 0x5658 | Some malware checks both VMware AND KVM |
| `host-passthrough` | CPUID vendor, model, features | QEMU presents `TCGTCGTCGTCG` / `qemu64` |
| `hypervisor` disabled | CPUID bit 31 in ECX (hypervisor present flag) | Windows sets this; malware reads it |
| Custom disk serial | WMI `Win32_DiskDrive.SerialNumber` | Default is `QEMU HARDDISK QM00001` |
| Intel MAC OUI | NIC vendor via `GetAdaptersInfo` | `52:54:00` is QEMU's default OUI, widely flagged |

---

## Step 10: Troubleshooting

### Packer fails to connect via WinRM

```bash
# Check if VM booted and WinRM is listening
virsh domstate win11-sandbox   # should be "running" during build

# WinRM port 5985 should be reachable from host
# During Packer build, QEMU uses port forwarding:
# host:5985 -> guest:5985 (Packer handles this automatically)

# If WinRM times out: autounattend.xml FirstLogonCommands may have failed
# Run build with headless=false to see the VM screen:
packer build -var='headless=false' win11-analysis.pkr.hcl
```

### Windows 11 installer says "This PC doesn't meet requirements"

```bash
# This means the LabConfig TPM/SecureBoot bypass didn't apply
# Check autounattend.xml RunSynchronous commands are correct
# Also ensure UEFI boot is enabled (efi_boot = true in HCL)
```

### FLARE-VM install hangs

```bash
# FLARE-VM can take 4+ hours on a slow host
# Increase winrm_timeout to "8h" in HCL
# Check Chocolatey log inside VM: C:\ProgramData\chocolatey\logs\chocolatey.log
# Connect with WinRM while build is running:
python3 -c "
import winrm
s = winrm.Session('localhost', auth=('analyst','malware123!'), transport='ntlm')
print(s.run_ps('Get-Process | Select-Object Name | Sort-Object Name').std_out)
"
```

### `/dev/kvm` permission denied

```bash
sudo chmod o+rw /dev/kvm
# OR add user to kvm group (requires re-login):
sudo usermod -aG kvm $USER
newgrp kvm
```

### qemu-img: backing file not found after move

```bash
# If you move the golden image, update the backing file reference:
qemu-img rebase -b /new/path/win11-analysis.qcow2 /vms/win11-sandbox.qcow2
```

---

## Step 11: Storage Layout

```
/isos/
  Win11_Eval_x64.iso           # source ISO (can delete after build)

/golden-images/
  win11-analysis.qcow2         # Packer output, ~30 GB, read-only source-of-truth
  win11-analysis.qcow2.sha256  # checksum for integrity verification

/vms/
  win11-sandbox.qcow2          # thin-clone (CoW), starts ~200 KB, grows per run
                               # rebased from golden-images/win11-analysis.qcow2
```

### Storage efficiency

- The golden image is ~30 GB (full install + FLARE-VM)
- The thin-clone starts at ~200 KB and grows only with per-session changes
- After `virsh snapshot-revert`, the clone disk is reset to its CoW baseline
- Multiple thin-clones can share one golden image for parallel runs

---

## Step 12: Keeping the Golden Image Fresh

| Schedule | Action |
|----------|--------|
| **Monthly** | `packer build -force` full rebuild (picks up latest FLARE-VM, Sysmon config) |
| **On Sysmon config update** | `virt-customize` patch (no rebuild needed, 5 minutes) |
| **On FakeNet config update** | `virt-customize` patch |
| **On Windows Eval expiry (90d)** | Download new ISO, full rebuild |
| **On FLARE-VM major release** | Full rebuild |

### Automate monthly rebuild (cron)

```bash
# /etc/cron.d/packer-golden-rebuild
0 2 1 * * analyst cd /opt/honeypot-stack && \
    packer build -force sandbox/windows/packer/win11-analysis.pkr.hcl && \
    sandbox/windows/setup/kvm_manage.sh create && \
    sandbox/windows/setup/kvm_manage.sh snapshot
```

---

## Summary: Full First-Time Setup Sequence

```bash
# 1. Install host dependencies
sudo apt install -y qemu-kvm qemu-utils libvirt-daemon-system \
    libvirt-clients ovmf packer genisoimage libguestfs-tools
packer plugins install github.com/hashicorp/qemu

# 2. Set up isolated libvirt network
virsh net-define sandbox/windows/packer/sandbox-network.xml
virsh net-autostart sandbox && virsh net-start sandbox

# 3. Place Windows 11 ISO
cp Win11_Eval_x64.iso /isos/

# 4. Update checksum in HCL
SHA=$(sha256sum /isos/Win11_Eval_x64.iso | cut -d' ' -f1)
sed -i "s|none:skip|sha256:${SHA}|" sandbox/windows/packer/win11-analysis.pkr.hcl

# 5. Build golden image (3-5 hours)
sudo chmod o+rw /dev/kvm
packer build sandbox/windows/packer/win11-analysis.pkr.hcl

# 6. Create VM from golden image
sandbox/windows/setup/kvm_manage.sh create

# 7. Take GOLDEN_READY snapshot
sandbox/windows/setup/kvm_manage.sh start
sleep 90   # wait for boot
sandbox/windows/setup/kvm_manage.sh snapshot

# 8. Test revert
sandbox/windows/setup/kvm_manage.sh revert

# Golden image pipeline is now operational.
# Each detonation run starts with: kvm_manage.sh revert (5-10s)
```
