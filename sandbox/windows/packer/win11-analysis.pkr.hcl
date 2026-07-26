# win11-analysis.pkr.hcl
# Packer build: Windows 11 analysis golden image for KVM/QEMU
# Based on: https://github.com/proactivelabs/packer-windows
# Requires: packer plugins install github.com/hashicorp/qemu
#
# Usage:
#   packer init win11-analysis.pkr.hcl
#   packer build win11-analysis.pkr.hcl
# Output: /golden-images/win11-analysis.qcow2

packer {
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = ">= 1.0.0"
    }
  }
}

variable "iso_path" {
  description = "Path to Windows 11 evaluation ISO"
  default     = "/isos/Win11_Eval_x64.iso"
}

variable "iso_checksum" {
  description = "SHA256 of ISO (update when downloading new ISO)"
  default     = "none:skip"  # replace with actual checksum
}

variable "output_dir" {
  default = "/golden-images"
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
  default = "90000"  # 90 GB — malware checks disk size
}

variable "winrm_user" {
  default = "analyst"
}

variable "winrm_pass" {
  default = "malware123!"
}

source "qemu" "win11" {
  # Boot from ISO
  iso_url          = var.iso_path
  iso_checksum     = var.iso_checksum

  # Output
  output_directory = var.output_dir
  vm_name          = "${var.vm_name}.qcow2"
  disk_image       = false
  format           = "qcow2"

  # Hardware — anti-sandbox-detection
  machine_type     = "q35"
  memory           = var.memory
  cpus             = var.cpus
  disk_size        = var.disk_size
  disk_interface   = "virtio"          # fast + common in real VMs
  net_device       = "e1000e"          # Intel NIC — looks real
  # host-passthrough: guest sees real CPU model, not QEMU default
  cpu_model        = "host"

  # UEFI boot (required for Windows 11)
  efi_boot         = true
  efi_firmware_code = "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd"
  efi_firmware_vars = "/usr/share/OVMF/OVMF_VARS_4M.ms.fd"

  # Floppy with autounattend.xml for unattended install
  floppy_files     = ["autounattend.xml"]

  # WinRM communicator (enabled by SetupComplete.cmd in autounattend)
  communicator     = "winrm"
  winrm_username   = var.winrm_user
  winrm_password   = var.winrm_pass
  winrm_timeout    = "6h"   # FLARE-VM takes 2-4 hours
  winrm_use_ssl    = false
  winrm_insecure   = true

  # Shutdown after provisioning
  shutdown_command = "shutdown /s /t 10 /f /d p:4:1 /c 'Packer build complete'"
  shutdown_timeout = "30m"

  # Accelerator
  accelerator      = "kvm"
  headless         = true

  # Boot wait for Windows installer
  boot_wait        = "3s"
  # No boot_command needed — autounattend.xml handles everything
}

build {
  name    = "win11-analysis"
  sources = ["source.qemu.win11"]

  # Step 1: Run main setup script (Chocolatey, FLARE-VM, Sysmon, logging, hardening)
  provisioner "powershell" {
    script          = "scripts/setup_analysis.ps1"
    elevated_user   = var.winrm_user
    elevated_password = var.winrm_pass
    # Long timeout for FLARE-VM install
    timeout         = "5h"
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
