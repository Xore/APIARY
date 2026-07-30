# win11-analysis.pkr.hcl
# Packer build: Windows 11 analysis golden image for KVM/QEMU
# Based on: https://github.com/proactivelabs/packer-windows
# Requires: packer plugins install github.com/hashicorp/qemu
#
# Build host requirements (all present on the analysis host as of 2026-07-30):
#   /dev/kvm, qemu-system-x86_64, swtpm  (TPM 2.0 emulation for Windows 11)
#   /usr/share/OVMF/OVMF_CODE_4M.secboot.fd + OVMF_VARS_4M.ms.fd
#
# Usage:
#   packer init win11-analysis.pkr.hcl
#   packer validate win11-analysis.pkr.hcl
#   packer build -var iso_checksum=sha256:<hex> win11-analysis.pkr.hcl
# Output: $output_dir/win11-analysis.qcow2  (~25-35 GB, 3-5 h)
#
# The ISO is not fetched here. Download the Windows 11 Enterprise evaluation
# yourself, accept Microsoft's licence, and place it at var.iso_path.

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
  # Deliberately on /var (1.5 TB spindle), not the 233 GB root NVMe. The ISO
  # is 6.5 GB and the golden image adds 25-35 GB on top; filling the OS disk
  # to build a sandbox image is not a trade worth making.
  default = "/var/dockge/sandbox/isos/Win11_Eval_x64.iso"
}

variable "iso_checksum" {
  description = <<-EOT
    Checksum of the Windows 11 evaluation ISO, as "sha256:<hex>".
    "none" skips verification — acceptable only for a hand-placed ISO whose
    provenance you already trust, because a tampered installer would be
    baked into every subsequent detonation guest. Prefer the real value:
      sha256sum /isos/Win11_Eval_x64.iso
  EOT
  default     = "none"
}

variable "output_dir" {
  # Same reasoning as iso_path: the qcow2 lives on the large disk.
  default = "/var/dockge/sandbox/golden-images"
}

variable "vm_name" {
  default = "win11-analysis"
}

variable "memory" {
  default = "8192"
}

variable "cpus" {
  default = "4"
}

variable "disk_size" {
  default = "90000" # 90 GB — malware checks disk size
}

variable "winrm_user" {
  default = "analyst"
}

variable "winrm_pass" {
  default = "malware123!"
}

source "qemu" "win11" {
  # Boot from ISO
  iso_url      = var.iso_path
  iso_checksum = var.iso_checksum

  # Output
  output_directory = var.output_dir
  vm_name          = "${var.vm_name}.qcow2"
  disk_image       = false
  format           = "qcow2"

  # Hardware — anti-sandbox-detection
  machine_type   = "q35"
  memory         = var.memory
  cpus           = var.cpus
  disk_size      = var.disk_size
  disk_interface = "virtio" # fast + common in real VMs
  net_device     = "e1000e" # Intel NIC — looks real
  # host-passthrough: guest sees real CPU model, not QEMU default
  cpu_model = "host"

  # UEFI + Secure Boot. Windows 11 setup refuses to install without both, and
  # the .ms firmware pair is the one with Microsoft's keys already enrolled.
  efi_boot          = true
  efi_firmware_code = "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd"
  efi_firmware_vars = "/usr/share/OVMF/OVMF_VARS_4M.ms.fd"

  # TPM 2.0 — the other hard Windows 11 requirement. Without it the installer
  # stops at "This PC can't run Windows 11" and the build hangs until
  # winrm_timeout expires with no usable diagnostic.
  #
  # Both settings are required. vtpm is the switch that makes the plugin start
  # swtpm and pass -tpmdev/-device to QEMU; tpm_device_type only chooses the
  # model. Setting the model alone is silently accepted by `packer validate`
  # and produces a QEMU command line with no TPM at all — verified by reading
  # /proc/<qemu>/cmdline on a run that had only tpm_device_type set.
  # /usr/bin/swtpm must exist on the build host.
  vtpm            = true
  tpm_device_type = "tpm-tis"

  # autounattend.xml is delivered on a secondary CD, not a floppy. The q35
  # machine type has no floppy controller, so floppy_files silently produces
  # an installer that sits on the language prompt forever.
  cd_files = ["autounattend.xml"]
  cd_label = "cidata"

  # WinRM communicator (enabled by SetupComplete.cmd in autounattend)
  communicator   = "winrm"
  winrm_username = var.winrm_user
  winrm_password = var.winrm_pass
  winrm_timeout  = "6h" # FLARE-VM takes 2-4 hours
  winrm_use_ssl  = false
  winrm_insecure = true

  # Shutdown after provisioning
  shutdown_command = "shutdown /s /t 10 /f /d p:4:1 /c 'Packer build complete'"
  shutdown_timeout = "30m"

  # Accelerator
  accelerator = "kvm"
  headless    = true

  # The Windows installer stops at "Press any key to boot from CD or DVD".
  # Nothing presses it in a headless build, so the firmware falls through to
  # the UEFI shell and the build hangs. Send the keypress, then let
  # autounattend.xml drive the rest of the install.
  boot_wait    = "2s"
  boot_command = ["<enter>"]
}

build {
  name    = "win11-analysis"
  sources = ["source.qemu.win11"]

  # Step 1: Run main setup script (Chocolatey, FLARE-VM, Sysmon, logging, hardening)
  provisioner "powershell" {
    script            = "scripts/setup_analysis.ps1"
    elevated_user     = var.winrm_user
    elevated_password = var.winrm_pass
    # Long timeout for FLARE-VM install
    timeout = "5h"
  }

  # Step 2: Final cleanup + sysprep-lite (do NOT full sysprep — breaks some tools)
  provisioner "powershell" {
    inline = [
      # Clear event logs (start fresh for analysis)
      "Get-EventLog -List | ForEach-Object { Clear-EventLog -LogName $_.Log -ErrorAction SilentlyContinue }",
      "wevtutil cl Microsoft-Windows-Sysmon/Operational",
      "wevtutil cl Microsoft-Windows-PowerShell/Operational",
      # Clear temp files
      "Remove-Item -Recurse -Force C:\\Windows\\Temp\\* -ErrorAction SilentlyContinue",
      "Remove-Item -Recurse -Force C:\\Users\\analyst\\AppData\\Local\\Temp\\* -ErrorAction SilentlyContinue",
      # Mark build timestamp
      "[System.IO.File]::WriteAllText('C:\\golden_image_build.txt', (Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'))",
      "Write-Output 'Golden image build complete'"
    ]
  }
}
