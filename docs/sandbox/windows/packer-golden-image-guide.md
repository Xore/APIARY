# Automating Golden Image Creation with Packer and QEMU
## Implementation Guide for KVM Host (honeypot-stack)

> **Host**: KVM + QEMU + libvirt + docker-compose (no VMware, no Hyper-V)  
> **Goal**: Fully automated, reproducible Windows 11 golden image as a `qcow2` file  
> **Reference**: [proactivelabs/packer-windows](https://github.com/proactivelabs/packer-windows), [actuated.com Packer+QEMU guide](https://actuated.com/blog/automate-packer-qemu-image-builds)

> **Status (2026-07-31):** the templates in `sandbox/windows/packer/` are
> written and `packer validate` passes. No golden image has been produced on
> this host yet. The steps below are the procedure, not a record of a completed
> run — treat every duration and size as an estimate until a build confirms
> them. Execution is tracked in
> [#49](https://github.com/Xore/honeypot-stack/issues/49) (obtain the ISO — operator action),
> [#51](https://github.com/Xore/honeypot-stack/issues/51) (run the build),
> [#52](https://github.com/Xore/honeypot-stack/issues/52) (define the domain, take `GOLDEN_READY`),
> under [#47](https://github.com/Xore/honeypot-stack/issues/47). Lifecycle gaps are
> [#86](https://github.com/Xore/honeypot-stack/issues/86).

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
  │     ├── 2. autounattend.xml on secondary CD → fully unattended install
  │     ├── 3. WinRM auto-enabled via FirstLogonCommands
  │     ├── 4. Packer connects via WinRM → runs PowerShell provisioners
  │     ├── 5. 01-hardening → 02-flarevm-start → 03-wait ×12 → 04-tools:
  │     │                        PS logging → FakeNet-NG → hardening
  │     └── 6. Shutdown → export win11-analysis.qcow2
  │
  └── /var/dockge/sandbox/golden-images/win11-analysis.qcow2  (25-35 GB)
        │
        ├── qemu-img create (thin clone) → /vms/win11-sandbox.qcow2
        └── virsh define → VM defined in libvirt
              │
              └── kvm_manage.sh revert: destroy + fresh CoW clone + start
                    (before each run, cold boot ~1-2min — see #358 for why
                    this isn't a virsh snapshot revert)
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

Windows 11 requires UEFI + TPM. The build gives it both for real: the `.ms`
OVMF firmware pair (Microsoft's keys already enrolled) and a software TPM from
`swtpm`. The `LabConfig` registry keys in `autounattend.xml` are a fallback, not
the mechanism — see Step 3.

```bash
sudo apt install -y ovmf swtpm swtpm-tools

# Verify firmware files exist
ls /usr/share/OVMF/
# Should include: OVMF_CODE_4M.secboot.fd, OVMF_VARS_4M.ms.fd
# If not found, try: /usr/share/qemu/OVMF.fd (path varies by distro)
```

### 0.5 Prepare image directories

Everything lives under `/var/dockge/sandbox` — deliberately on the 1.5 TB `/var`
spindle rather than the 233 GB root NVMe. The ISO is 6.5 GB and the golden image
adds 25-35 GB on top; filling the OS disk to build a sandbox image is not a
trade worth making.

```bash
sudo mkdir -p /var/dockge/sandbox/{golden-images,vms,isos}
sudo chown -R $USER:$USER /var/dockge/sandbox
```

The paths are defaults in three places that cannot read each other:
`iso_path` / `output_dir` in `win11-analysis.pkr.hcl`, `SANDBOX_ROOT` in
`setup/kvm_manage.sh` (overridable by environment), and the `<source file>`
element in `packer/win11-kvm.xml` (hardcoded). Change one and you must change
all three. The shorthand `/golden-images`, `/vms` and `/isos` used in the
commands below is for readability — substitute the real prefix.

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

File: [`sandbox/windows/packer/win11-analysis.pkr.hcl`](../../../sandbox/windows/packer/win11-analysis.pkr.hcl)

### Key sections explained

#### QEMU source block

```hcl
source "qemu" "win11" {
  accelerator      = "kvm"          # Hardware acceleration via KVM
  machine_type     = "q35"          # Modern PCIe chipset (required for UEFI)
  efi_boot         = true           # UEFI required for Windows 11
  efi_firmware_code = "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd"
  efi_firmware_vars = "/usr/share/OVMF/OVMF_VARS_4M.ms.fd"
  vtpm             = true           # starts swtpm; without it setup refuses
  tpm_device_type  = "tpm-tis"      # model only — not a substitute for vtpm
  cpu_model        = "host"         # Pass-through real CPU — anti-sandbox-detection
  disk_interface   = "ide"          # ICH9 AHCI on q35 — see below
  net_device       = "e1000e"       # Intel NIC model — looks like real hardware
  cd_files         = ["autounattend.xml"]  # secondary CD, not a floppy
  cd_label         = "cidata"
  communicator     = "winrm"        # Packer connects via WinRM after install
  winrm_timeout    = "45m"          # wait for WinRM to *first* answer
  headless         = true           # No GUI window on KVM host
}
```

The file itself carries the full reasoning for each of these in comments; what
follows is the short version of the four that are counter-intuitive.

#### Why `disk_interface = "ide"` and not `virtio`?

Windows 11 setup has no virtio-blk driver, so a virtio disk is invisible to the
installer and the unattended install stops at "no drives found". A virtio
controller is also one of the loudest "you are in a VM" signals a sample can
read. The value is `"ide"` rather than `"sata"` because QEMU's `-drive if=`
knows no sata bus and refuses to start; on q35 the `ide` bus *is* the ICH9 AHCI
controller, so the guest sees a SATA disk regardless of the option's name.

#### Why `cd_files` and not `floppy_files`?

The q35 machine type has no floppy controller. `floppy_files` is silently
accepted and produces an installer that sits on the language prompt forever.

#### Why both `vtpm` and `tpm_device_type`?

`vtpm = true` is the switch that makes the plugin start `swtpm` and pass
`-tpmdev`/`-device` to QEMU. `tpm_device_type` only chooses the model. Setting
the model alone passes `packer validate` and produces a QEMU command line with
no TPM at all. `/usr/bin/swtpm` must exist on the build host.

#### What `winrm_timeout` actually bounds

It is the wait for WinRM to answer for the first time — not the provisioning
budget, which is the provisioner's own `timeout = "5h"`. FLARE-VM runs *after*
this connects. It was `6h` on the theory that FLARE-VM takes 2-4 hours; the only
thing that bought was that a guest which never brings WinRM up burns a whole
working day before saying so. Install plus OOBE is well under 45 minutes here.

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

File: [`sandbox/windows/packer/autounattend.xml`](../../../sandbox/windows/packer/autounattend.xml)

This XML file is the Windows unattended installation answer file. Packer
passes it on a secondary CD labelled `cidata`; Windows Setup scans removable
media for it automatically on boot.

### Key elements

#### TPM/SecureBoot bypass (critical for KVM)

```xml
<RunSynchronousCommand>
  <Path>reg add HKLM\SYSTEM\Setup\LabConfig /v BypassTPMCheck /t REG_DWORD /d 1 /f</Path>
</RunSynchronousCommand>
<RunSynchronousCommand>
  <Path>reg add HKLM\SYSTEM\Setup\LabConfig /v BypassSecureBootCheck /t REG_DWORD /d 1 /f</Path>
</RunSynchronousCommand>
<RunSynchronousCommand>
  <Path>reg add HKLM\SYSTEM\Setup\LabConfig /v BypassRAMCheck /t REG_DWORD /d 1 /f</Path>
</RunSynchronousCommand>
```

Windows 11 requires TPM 2.0, SecureBoot and a RAM floor. The build satisfies
the first two for real — `vtpm = true` starts `swtpm`, and the `.ms` OVMF
firmware pair ships with Microsoft's keys enrolled — so these `LabConfig` keys
are a second line of defence rather than the mechanism. They are cheap to keep:
they cost nothing when the hardware is present and they turn a hang at "This PC
can't run Windows 11" into a completed install if a host is missing `swtpm`.
The build VM is sized at 8 GB, so `BypassRAMCheck` is inert at the default
`memory` value and only matters if someone shrinks it.

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
  <SynchronousCommand><Order>1</Order>
    <CommandLine>powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private -ErrorAction SilentlyContinue; Enable-PSRemoting -Force -SkipNetworkProfileCheck"</CommandLine>
  </SynchronousCommand>
  <!-- 2: AllowUnencrypted   3: Basic auth   4: firewall rule for 5985
       5: add analyst to "Remote Management Users" -->
  <SynchronousCommand><Order>6</Order>
    <CommandLine>powershell -NoProfile -Command "Set-Service WinRM -StartupType Automatic; Start-Service WinRM; Set-Content -Path C:\winrm-ready.txt -Value (Get-Date -Format o)"</CommandLine>
  </SynchronousCommand>
</FirstLogonCommands>
```

Packer connects to the Windows VM via WinRM (Windows Remote Management)
over port 5985. The `FirstLogonCommands` enable WinRM before the first
login completes, so Packer can start running provisioners immediately.

#### Why not `winrm quickconfig -q`?

That was the original order 1 and it cost a six-hour build. `winrm quickconfig`
refuses to create its firewall exception while any connection profile is Public
— which is exactly what a fresh guest on QEMU user-mode networking has — and
exits non-zero. The remaining commands then went on to configure a service that
had never been enabled, so the guest looked healthy from inside and never
answered from outside. Forcing the profile to Private first and using
`Enable-PSRemoting -Force -SkipNetworkProfileCheck` is what actually brings it
up.

`C:\winrm-ready.txt` exists to separate two failure modes that otherwise look
identical from the host: OOBE never reached first logon, versus first logon ran
and WinRM still did not come up. Mount the qcow2 (or take a screenshot with
`headless=false`) and check for the file.

---

## Step 4: The Provisioner Script

File: [`sandbox/windows/packer/scripts/`](../../../sandbox/windows/packer/scripts/) (01-hardening, 02-flarevm-start, 03-flarevm-wait, 04-tools)

This runs inside the Windows VM via WinRM during the Packer build.
It has 14 sequential phases, numbered in the script's own `[Phase n]` output:

| Phase | Action | Notes |
|-------|--------|-------|
| 1 | Network config | Real DNS during build (Chocolatey needs internet), INetSim DNS set at end |
| 2 | Disable Defender | Real-time, cloud, MAPS, sample submission |
| 3 | Disable Windows Update | Service + GPO |
| 4 | Disable Telemetry | `DiagTrack`, `dmwappushservice`, registry |
| 5 | Disable UAC | Required for unattended tool installs |
| 6 | Disable Firewall | FakeNet-NG handles all traffic; SmartScreen is disabled in this phase too |
| 7 | Install Chocolatey | Package manager for FLARE-VM |
| 8 | Install FLARE-VM | 100+ analysis tools, takes 2-4 hours |
| 9 | Install Sysmon | With SwiftOnSecurity config |
| 10 | PowerShell logging | ScriptBlock (4104), Module (4103), Transcription; also process auditing (4688) |
| 11 | Install FakeNet-NG | Network interception on guest |
| 12 | Install QEMU Guest Agent | Enables host-side file copy via guest agent |
| 13 | Decoy environment | Fake documents, browser history, recent files |
| 14 | Set DNS to INetSim | Final step: all DNS → 10.10.10.1 |

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

Do not `sed` the HCL. `iso_path` and `iso_checksum` are declared variables with
defaults; pass them on the command line so the file stays clean and the build is
reproducible from the shell history.

```bash
cd sandbox/windows/packer

# 1. Compute the ISO checksum
ISO=/var/dockge/sandbox/isos/Win11_Eval_x64.iso
SHA=$(sha256sum "$ISO" | cut -d' ' -f1)

# 2. (variables are passed to `packer build` in step 5)

# 3. Initialise Packer plugins
packer init win11-analysis.pkr.hcl

# 4. Validate the template
packer validate win11-analysis.pkr.hcl

# 5. Build (takes 3-5 hours)
# /dev/kvm must be accessible
sudo chmod o+rw /dev/kvm   # or add user to kvm group and re-login

packer build \
  -var "iso_path=$ISO" \
  -var "iso_checksum=sha256:${SHA}" \
  win11-analysis.pkr.hcl

# Output:
#   /var/dockge/sandbox/golden-images/win11-analysis.qcow2   (25-35 GB)
```

Leaving `iso_checksum` at its `"none"` default skips verification entirely. That
is acceptable only for a hand-placed ISO whose provenance you already trust: a
tampered installer would be baked into every subsequent detonation guest.

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

The helper is the supported path: it reads `packer/win11-kvm.xml`, which carries
the anti-detection settings in Step 9. `virt-install` produces a domain without
them, so use it only for a throwaway boot test:
```bash
virt-install \
  --name win11-sandbox \
  --memory 8192 \
  --vcpus 4 \
  --cpu host \
  --disk path=/var/dockge/sandbox/vms/win11-sandbox.qcow2,bus=sata,cache=none \
  --network network=sandbox,model=e1000e \
  --os-variant win11 \
  --boot uefi \
  --graphics none \
  --import \
  --noautoconsole
```

### Verify the domain boots

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
```

There is no `virsh snapshot-create-as GOLDEN_READY` step. It looks like it
should work here — the guest is running, WinRM is up — but this domain's
`<cpu mode='host-passthrough' migratable='off'/>` (deliberate, for anti-VM-
detection CPU fidelity) blocks memory-state snapshots outright, and
disk-only snapshots hit a separate, reproducible QEMU/libvirt bug on the
resulting multi-layer backing chain (see #358 for the full investigation —
a freshly spawned qemu process fails to open the golden image even though
file permissions are provably fine). The golden image is already never
written to, so there's nothing to snapshot: every reset just throws away
the per-run CoW clone and makes a fresh one.

---

## Step 7: Reset Workflow for Analysis Runs

### Before every detonation run

```bash
# Reset to a fresh clone of the golden image (cold boot, ~1-2 min)
sandbox/windows/setup/kvm_manage.sh revert

# Wait for WinRM, then run your sample
python3 sandbox/windows/orchestrate/run_sample.py --sample samples/PE/evil.exe
```

`run_sample.py` calls the equivalent of this itself before and after every
detonation (`revert_to_golden()`) — the above is for manual/ad-hoc runs.

### After every run (handled automatically by run_sample.py)

Same reset, always run in the `finally` block regardless of success/failure
— the guest has run untrusted code and must never survive into the next
sample.

---

## Step 8: Rebuilding and Updating the Golden Image

### Full rebuild (e.g. FLARE-VM update, quarterly refresh)

```bash
# Remove old VM first
virsh destroy win11-sandbox 2>/dev/null || true
virsh undefine win11-sandbox --nvram
rm /vms/win11-sandbox.qcow2

# Rebuild golden image from scratch
packer build -force sandbox/windows/packer/win11-analysis.pkr.hcl

# Recreate VM
sandbox/windows/setup/kvm_manage.sh create
sandbox/windows/setup/kvm_manage.sh start
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

# After patching qcow2, recreate the thin-clone
rm /vms/win11-sandbox.qcow2
sandbox/windows/setup/kvm_manage.sh create
sandbox/windows/setup/kvm_manage.sh start
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

Do **not** raise `winrm_timeout` in response to this. It bounds the wait for
WinRM to answer once, not the FLARE-VM install, so a longer value cannot rescue
a guest that is never going to answer — it only delays the report. 45 minutes is
already generous for install plus OOBE on this host. Diagnose instead: check for
`C:\winrm-ready.txt` in the guest. Present means first logon ran and the
failure is networking or the firewall rule; absent means the guest never
reached first logon, and the cause is upstream — media, boot keypress, or the
installer stopping on a hardware check.

### Build ends at "No bootable option or device was found"

The "Press any key to boot from CD or DVD" prompt has to be answered while it is
on screen, and that window is narrow and late: OVMF spends roughly fifteen
seconds initialising, then the prompt lasts about five. A single keypress at
`boot_wait = "2s"` lands in the firmware before the prompt exists, is discarded,
and the guest falls through — which reads like broken media rather than a timing
bug. The template keeps `boot_wait` short and spams Enter across the whole
window. Extra presses after the installer has started are harmless.

### Windows 11 installer says "This PC doesn't meet requirements"

```bash
# This means the LabConfig TPM/SecureBoot bypass didn't apply
# Check autounattend.xml RunSynchronous commands are correct
# Also ensure UEFI boot is enabled (efi_boot = true in HCL)
```

### FLARE-VM install hangs

```bash
# FLARE-VM can take 4+ hours on a slow host. The knob is the *provisioner's*
# timeout (currently "5h") in the build block — not winrm_timeout, which has
# already been satisfied by the time FLARE-VM starts.
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
/var/dockge/sandbox/isos/
  Win11_Eval_x64.iso           # source ISO, 6.5 GB (can delete after build)

/var/dockge/sandbox/golden-images/
  win11-analysis.qcow2         # Packer output, 25-35 GB, read-only source-of-truth
  win11-analysis.qcow2.sha256  # NOT WRITTEN — nothing generates or checks it (#86)

/var/dockge/sandbox/vms/
  win11-sandbox.qcow2          # thin-clone (CoW), starts ~200 KB, grows per run
                               # rebased from golden-images/win11-analysis.qcow2
```

The qcow2 is sparse: `disk_size = 90000` gives the guest a 90 GB disk because
malware checks disk size, but the file on the host only grows to what is
actually written.

### Storage efficiency

- The golden image is 25-35 GB (full install + FLARE-VM)
- The thin-clone starts at ~200 KB and grows only with per-session changes
- Each `kvm_manage.sh revert` deletes the clone and recreates it fresh from the golden image
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

This cadence is currently manual. Automating it is **[#86](https://github.com/Xore/honeypot-stack/issues/86)**, which is
not the one-line cron entry it looks like: a 3-5 hour build cannot share
`/dev/kvm` with a detonation run, `-force` would destroy the working image
before the replacement is known good, and a rebuild against an expired
evaluation ISO produces an already-expired guest.

---

## Summary: Full First-Time Setup Sequence

```bash
# 1. Install host dependencies
sudo apt install -y qemu-kvm qemu-utils libvirt-daemon-system \
    libvirt-clients ovmf swtpm swtpm-tools packer genisoimage libguestfs-tools
packer plugins install github.com/hashicorp/qemu
which swtpm   # must exist, or vtpm = true starts no TPM and setup refuses

# 2. Set up isolated libvirt network
virsh net-define sandbox/windows/setup/sandbox-network.xml
virsh net-autostart sandbox && virsh net-start sandbox

# 3. Place Windows 11 ISO
ISO=/var/dockge/sandbox/isos/Win11_Eval_x64.iso
cp Win11_Eval_x64.iso "$ISO"

# 4. Compute the checksum
SHA=$(sha256sum "$ISO" | cut -d' ' -f1)

# 5. Build golden image (3-5 hours)
sudo chmod o+rw /dev/kvm
packer build -var "iso_path=$ISO" -var "iso_checksum=sha256:${SHA}" \
    sandbox/windows/packer/win11-analysis.pkr.hcl

# 6. Create VM from golden image
sandbox/windows/setup/kvm_manage.sh create

# 7. Verify it boots
sandbox/windows/setup/kvm_manage.sh start
sleep 90   # wait for boot

# 8. Test reset (destroy + fresh CoW clone + start)
sandbox/windows/setup/kvm_manage.sh revert

# Golden image pipeline is then operational.
# Each detonation run starts with: kvm_manage.sh revert (5-10s)
```
