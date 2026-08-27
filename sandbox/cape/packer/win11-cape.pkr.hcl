# win11-cape.pkr.hcl
# Packer build: CAPE detonation golden image for KVM/QEMU (#315)
#
# Adapted directly from sandbox/windows/packer/win11-analysis.pkr.hcl --
# same PXE boot mechanism, same anti-detection hardware posture, same
# retry-worthy WinRM quirks. Differences from that file, and only these:
#   * vm_name/output: win11-cape, not win11-analysis
#   * provisioners: 01-hardening.ps1 (copied, see its own header) + a new
#     02-cape-agent.ps1 (32-bit Python + CAPE's agent.pyw, per CAPEv2's own
#     upstream docs, read directly off the real checkout on this host
#     rather than assumed) -- NOT the sandbox/windows-specific decoy-
#     content/chrome-history/persona-daemon/traffic-noise/vcredist/
#     loldrivers/detonation-orchestrator scripts, none of which apply to
#     CAPE's own, separate detonation architecture (CAPE's own cuckoo.py
#     drives the guest via agent.py, not this repo's run_sample.py)
#   * final cleanup: DNS pinned to 10.40.50.1 (virbr-cape's gateway),
#     not 10.10.10.1 (virbr-sandbox's)
#   * PXE boot files: reused IN PLACE from the existing prepared directory
#     at pxe_dir below, rather than a second copy -- see that variable's
#     own comment for why this is safe to share
#
# NEVER mount the ISO as a bootable CD-ROM and boot from it directly --
# see win11-analysis.pkr.hcl's own extensive PXE-vs-CD-boot comment
# (#288/#406) for the full account of why that path is structurally flaky
# (a keystroke race against "Press any key to boot from CD or DVD" that
# missed far more often than it hit across a full night of builds). The
# ISO is still attached (iso_url below) -- Windows Setup needs its install
# files from *somewhere* -- but the firmware never boots from it; PXE does
# that instead, exactly as win11-analysis.pkr.hcl already established.
#
# Build host requirements (already met on this host, which also builds
# win11-analysis.pkr.hcl):
#   /dev/kvm, qemu-system-x86_64, swtpm (TPM 2.0 emulation for Windows 11)
#   /usr/share/OVMF/OVMF_CODE_4M.fd + OVMF_VARS_4M.fd -- the non-secboot
#     pair this file's source block actually loads; deliberately not the
#     secboot pair win11-analysis.pkr.hcl's requirements list also names,
#     see the comment above the efi_firmware_* lines in the source block
#
# Usage:
#   packer init win11-cape.pkr.hcl
#   packer validate win11-cape.pkr.hcl
#   packer build -var iso_checksum=sha256:<hex> win11-cape.pkr.hcl
# Output: $output_dir/win11-cape.qcow2 (~25-35 GB, 3-5 h)
#
# Prefer build-with-retry.sh <checksum> [max_attempts] over calling `packer
# build` directly -- same WinRM-transport-error retry reasoning
# win11-analysis.pkr.hcl's own header gives (#194).
#
# The ISO is not fetched here. This host already has
# /var/dockge/sandbox/isos/Win11_Eval_x64.iso (the same Microsoft Windows
# 11 Enterprise evaluation build win11-analysis.qcow2 and win11-ghosts.qcow2
# were both built from) -- no separate licensed ISO needed for this build.

packer {
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = ">= 1.0.0"
    }
  }
}

variable "iso_path" {
  description = "Path to the Windows 11 installation ISO"
  default     = "/var/dockge/sandbox/isos/Win11_Eval_x64.iso"
}

variable "iso_checksum" {
  description = <<-EOT
    Checksum of the Windows 11 evaluation ISO, as "sha256:<hex>".
    Same ISO win11-analysis.pkr.hcl already builds from -- reuse its
    known-good checksum (see build-with-retry.sh invocations in this
    repo's history) rather than re-deriving one, unless the ISO file has
    changed since.
  EOT
  default     = "none"
}

variable "output_dir" {
  # NOT /var/dockge/sandbox/golden-images directly, unlike
  # win11-analysis.pkr.hcl's own default. Confirmed live: Packer's qemu
  # builder refuses to run at all when output_directory already exists
  # ("It must not exist"), and that directory already holds
  # win11-analysis.qcow2/win11-ghosts.qcow2 from prior builds -- an
  # isolated, guaranteed-fresh staging directory is what actually lets
  # this build run without touching either of those. build-with-retry.sh
  # moves the finished win11-cape.qcow2 into the shared directory and
  # removes this one after a successful build, not before.
  default = "/var/dockge/sandbox/golden-images/.building-win11-cape"
}

variable "vm_name" {
  default = "win11-cape"
}

variable "memory" {
  # Same as win11-analysis.pkr.hcl. #320's resource-coexistence decision
  # (host-wide KVM-detonation lock) means this and win11-sandbox's guest
  # never actually run detonations concurrently, so they can share the
  # same per-guest sizing without the host ever needing to serve both at
  # once.
  default = "16384"
}

variable "cpus" {
  default = "12"
}

variable "disk_size" {
  default = "90000" # 90 GB -- malware checks disk size
}

variable "winrm_user" {
  default = "analyst"
}

variable "winrm_pass" {
  default = "malware123!"
}

# PXE staging directory. Reused IN PLACE from win11-analysis.pkr.hcl's own
# prepared output, not duplicated: ipxe.efi (compiled + self-signed),
# wimboot, and the BCD/BOOT.SDI/boot.wim extracted from the ISO have
# nothing win11-analysis-specific about them -- they are purely a function
# of the pinned ISO, which this build shares. Duplicating gigabytes of
# build artifacts for an identical PXE chain would be pure waste. If this
# ever needs to diverge (a different ISO, a different signing cert), copy
# sandbox/windows/packer/pxe/ wholesale and run prepare-pxe.sh fresh in the
# copy -- don't edit the shared one out from under win11-analysis's own
# builds.
variable "pxe_dir" {
  default = "/var/dockge/stacks/apiary/sandbox/windows/packer/pxe"
}

source "qemu" "win11cape" {
  iso_url      = var.iso_path
  iso_checksum = var.iso_checksum

  output_directory = var.output_dir
  vm_name          = "${var.vm_name}.qcow2"
  disk_image       = false
  format           = "qcow2"

  machine_type   = "q35"
  memory         = var.memory
  cpus           = var.cpus
  disk_size      = var.disk_size
  disk_interface = "ide" # see win11-analysis.pkr.hcl's own comment: Windows
                          # 11 setup carries no virtio-blk driver, and AHCI
                          # reads as real hardware rather than a VM tell
  net_device = "e1000e"
  cpu_model  = "host"

  # Non-secboot OVMF, deliberate: this PXE chain was debugged under
  # non-secboot, and the one SECBOOT run attempted back then failed
  # differently (initial PXE fine, then a firmware boot-order fallthrough
  # to "No bootable option" -- the full account and the swap-back plan
  # live in win11-analysis.pkr.hcl's "Secure Boot OFF for now -- TEMPORARY"
  # comment block, #288/#419, above that file's own efi_firmware_* lines).
  # Revisit secure boot only once that reset is root-caused; the pair to
  # move to then is OVMF_CODE_4M.secboot.fd + OVMF_VARS_4M.ms.fd.
  efi_boot          = true
  efi_firmware_code = "/usr/share/OVMF/OVMF_CODE_4M.fd"
  efi_firmware_vars = "/usr/share/OVMF/OVMF_VARS_4M.fd"

  vtpm            = true
  tpm_device_type = "tpm-tis"

  cd_files = ["autounattend.xml"]
  cd_label = "cidata"

  communicator   = "winrm"
  winrm_username = var.winrm_user
  winrm_password = var.winrm_pass
  winrm_timeout  = "45m"
  winrm_use_ssl  = false
  winrm_insecure = true

  shutdown_command = "shutdown /s /t 10 /f /d p:4:1 /c \"Packer build complete\""
  shutdown_timeout = "30m"

  accelerator = "kvm"
  headless    = true

  # Own VNC port, distinct from win11-analysis's fixed 5999 -- both builds
  # must never run at once anyway (#320's shared KVM lock is a detonation-
  # time rule, not a build-time one, but two Packer builds sharing a VNC
  # port would still collide), but a distinct port removes the question
  # entirely rather than relying on that discipline.
  vnc_port_min = 5998
  vnc_port_max = 5998

  # PXE boot, not CD-ROM boot -- see this file's own header and
  # win11-analysis.pkr.hcl's #288/#406 comment for the full account of why.
  # Own QMP socket path so pxe/unplug-pxe-on-reset.sh (started separately,
  # pointed at this path) doesn't race win11-analysis's own build.
  qemuargs = [
    ["-qmp", "unix:/tmp/win11-cape-qmp.sock,server,nowait"],
    ["-device", "e1000e,netdev=pxenet0,bootindex=1,id=pxenet0dev"],
    ["-netdev", "user,id=pxenet0,net=10.0.4.0/24,dhcpstart=10.0.4.15,tftp=${var.pxe_dir},bootfile=ipxe.efi"],
    ["-device", "e1000e,netdev=user.0"],
    ["-netdev", "user,id=user.0,net=10.0.5.0/24,dhcpstart=10.0.5.15,hostfwd=tcp::{{ .SSHHostPort }}-:5985"],
  ]
}

build {
  name    = "win11-cape"
  sources = ["source.qemu.win11cape"]

  # Stage the CAPE agent for 02-cape-agent.ps1 to install. Destination is
  # Temp because it is the one directory guaranteed to exist before any
  # provisioner has run -- same convention win11-analysis.pkr.hcl's own
  # fakenet.ini staging step uses.
  provisioner "file" {
    source      = "agent/agent.py"
    destination = "C:/Windows/Temp/agent.py"
  }

  # Step 1: hardening + Chocolatey (copied from sandbox/windows, see its
  # own header for why reuse is correct here).
  provisioner "powershell" {
    script            = "scripts/01-hardening.ps1"
    elevated_user     = var.winrm_user
    elevated_password = var.winrm_pass
    timeout           = "30m"
  }

  # Step 2: settle the guest before installing tooling -- same cheap
  # insurance win11-analysis.pkr.hcl keeps against a pending reboot.
  provisioner "windows-restart" {
    restart_timeout = "30m"
  }

  # Step 3: 32-bit Python + CAPE's agent.pyw, per CAPEv2's own docs.
  provisioner "powershell" {
    script            = "scripts/02-cape-agent.ps1"
    elevated_user     = var.winrm_user
    elevated_password = var.winrm_pass
    timeout           = "30m"
  }

  # Step 4: final cleanup -- same structure win11-analysis.pkr.hcl's own
  # step 7 uses (each native call forced back to $LASTEXITCODE=0, ending on
  # an explicit exit 0), for the exact reason that file's own comment
  # records (a single native-command exit code silently became a whole
  # provisioner's failure once already, deleting a multi-hour build's
  # entire output directory for no real reason).
  provisioner "powershell" {
    inline = [
      "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters' -Name EnablePrefetcher -Value 3 -Type DWord -Force -ErrorAction SilentlyContinue",
      # virbr-cape's own gateway (10.40.50.1) -- harmless under the default
      # 'drop' route (#316) since nothing resolves anyway, and correct in
      # advance if a future CAPE-dedicated INetSim instance lands on this
      # same address -- per network.xml's own header block (the inetsim
      # paragraph there leaves such an instance as follow-up work).
      "$adapter = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1; Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses '10.40.50.1'",
      "Get-EventLog -List | ForEach-Object { Clear-EventLog -LogName $_.Log -ErrorAction SilentlyContinue }",
      "wevtutil cl Microsoft-Windows-Sysmon/Operational 2>$null; $global:LASTEXITCODE = 0",
      "wevtutil cl Microsoft-Windows-PowerShell/Operational 2>$null; $global:LASTEXITCODE = 0",
      "Remove-Item -Recurse -Force C:\\Windows\\Temp\\* -ErrorAction SilentlyContinue",
      "Remove-Item -Recurse -Force C:\\Users\\analyst\\AppData\\Local\\Temp\\* -ErrorAction SilentlyContinue",
      "[System.IO.File]::WriteAllText('C:\\golden_image_build.txt', (Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'))",
      "Write-Output 'CAPE golden image build complete'",
      "exit 0"
    ]
  }
}
