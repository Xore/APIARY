packer {
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = ">= 1.1.0"
    }
  }
}

variable "iso_url" {
  type    = string
  default = "/opt/iso/Win11_24H2_English_x64.iso"
}

variable "iso_checksum" {
  type    = string
  default = "sha256:REPLACE_WITH_ISO_SHA256"
}

variable "vm_password" {
  type      = string
  default   = "P@ssw0rd!Fin"
  sensitive = true
}

variable "headless" {
  type    = bool
  default = true
}

source "qemu" "win11_finance" {
  iso_url          = var.iso_url
  iso_checksum     = var.iso_checksum
  output_directory = "output-win11"
  vm_name          = "win11-finance-detnode.qcow2"
  format           = "qcow2"
  accelerator      = "kvm"

  cpus           = 4
  memory         = 8192
  disk_size      = "80G"
  disk_interface = "virtio"
  net_device     = "virtio-net"
  headless       = var.headless
  machine_type   = "q35"

  # UEFI firmware. TPM/SecureBoot checks are bypassed via LabConfig
  # registry keys in autounattend.xml, so no swtpm needed.
  # If OVMF_CODE_4M does not exist on your distro, try:
  #   /usr/share/OVMF/OVMF_CODE.fd  or  /usr/share/edk2/ovmf/OVMF_CODE.fd
  firmware = "/usr/share/OVMF/OVMF_CODE_4M.fd"

  # Look like corporate Dell hardware instead of a KVM guest
  qemuargs = [
    ["-cpu", "host,hv_relaxed,hv_spinlocks=0x1fff,hv_vapic,hv_time"],
    ["-smbios", "type=0,vendor=Dell Inc.,version=1.24.0"],
    ["-smbios", "type=1,manufacturer=Dell Inc.,product=OptiPlex 7010,serial=7XQ9VM2,uuid=4c4c4544-0058-5110-8058-b9c04f564d32"],
    ["-smbios", "type=3,manufacturer=Dell Inc."],
    ["-usb", "-device", "usb-tablet"]
  ]

  # Secondary ISO carrying the answer file + provisioning scripts
  cd_files = [
    "./answer/autounattend.xml",
    "./provision/*",
    "./fakenet/*"
  ]
  cd_label = "PROVISION"

  communicator   = "winrm"
  winrm_username = "mwilson"
  winrm_password = var.vm_password
  winrm_timeout  = "60m"
  winrm_insecure = true
  winrm_use_ssl  = false

  shutdown_command = "shutdown /s /t 10 /f /d p:4:1 /c \"Packer Shutdown\""
  shutdown_timeout = "15m"
}

build {
  sources = ["source.qemu.win11_finance"]

  provisioner "powershell" {
    inline = [
      "Start-Sleep -Seconds 30",
      "Write-Host '== detnode provisioning start =='",
      "New-Item -ItemType Directory -Force -Path C:\\ProgramData\\persona | Out-Null"
    ]
  }

  provisioner "powershell" { script = "provision/10-baseline.ps1" }
  provisioner "powershell" { script = "provision/30-tools.ps1" }
  provisioner "powershell" { script = "provision/20-persona.ps1" }
  provisioner "powershell" { script = "provision/40-fakenet.ps1" }

  provisioner "windows-restart" { restart_timeout = "30m" }

  provisioner "powershell" { script = "provision/50-chrome-history.ps1" }
  provisioner "powershell" { script = "provision/60-living-persona.ps1" }
  provisioner "powershell" { script = "provision/70-traffic-noise.ps1" }

  provisioner "windows-restart" { restart_timeout = "30m" }

  provisioner "powershell" { script = "provision/90-cleanup.ps1" }
}
