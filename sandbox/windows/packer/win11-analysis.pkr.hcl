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
  # 16 GB of the host's 91 GB. Two payoffs at once: FLARE-VM unpacks a great
  # deal of tooling and benefits from the page cache, and a guest with 8 GB
  # reads as a sandbox to anything that looks — the same reasoning that put
  # disk_size at 90 GB. Leaves ~54 GB for Elasticsearch and the sensors, which
  # share this host.
  default = "16384"
}

variable "cpus" {
  # 8 of the host's 16 threads. QEMU was pinning all four of the previous
  # allocation (291% CPU) through the install, and FLARE-VM — the two-to-four
  # hour phase — is the part that actually parallelises. Leaves 8 threads for
  # the honeypot stack running alongside.
  default = "8"
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
  machine_type = "q35"
  memory       = var.memory
  cpus         = var.cpus
  disk_size    = var.disk_size
  # AHCI, not virtio. Two reasons, and they point the same way:
  #
  # Windows 11 setup ships no virtio-blk driver, so a virtio disk simply does
  # not appear — setup stops on "Select location to install Windows 11" with
  # an empty disk list and "Hardware not showing up?". Supplying the driver
  # would mean carrying the virtio-win ISO and a driver path in the answer
  # file.
  #
  # And a virtio controller is itself one of the loudest "you are in a VM"
  # signals a sample can read. This guest is meant to look like a physical
  # workstation, so AHCI is the better disguise as well as the one that
  # installs unattended. The cost is throughput, which does not matter for a
  # guest that runs one sample at a time.
  #
  # The value is "ide", not "sata": QEMU's -drive if= knows no sata bus and
  # refuses to start with "unsupported bus type 'sata'". On the q35 machine
  # type the ide bus *is* the ICH9 AHCI controller, so the guest sees a SATA
  # disk regardless of what the option is called.
  disk_interface = "ide"
  net_device     = "e1000e" # Intel NIC — likewise real hardware, not virtio-net
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
  # Time to wait for WinRM to first answer — not the provisioning budget,
  # which is the provisioner's own timeout below. It was 6h on the theory that
  # FLARE-VM takes 2-4 hours, but FLARE-VM runs *after* this connects. The
  # only thing a 6h value buys is that a guest which never brings WinRM up
  # burns a whole working day before saying so, which is exactly what
  # happened. Install plus OOBE is well under 45 minutes on this host.
  winrm_timeout  = "45m"
  winrm_use_ssl  = false
  winrm_insecure = true

  # Shutdown after provisioning
  # Windows shutdown wants double quotes around /c. With single quotes it
  # rejects the arguments, prints its usage text, never shuts down, and the
  # build then sits out the whole shutdown_timeout below.
  shutdown_command = "shutdown /s /t 10 /f /d p:4:1 /c \"Packer build complete\""
  shutdown_timeout = "30m"

  # Accelerator
  accelerator = "kvm"
  headless    = true

  # "Press any key to boot from CD or DVD" has to be answered while it is on
  # screen, and that window is narrow and late: OVMF spends roughly fifteen
  # seconds initialising first, then the prompt lasts about five. A single
  # keypress at boot_wait = 2s is delivered into the firmware long before the
  # prompt exists, is discarded, and the guest falls through to
  # "No bootable option or device was found" — which looks like broken media
  # rather than a timing bug.
  #
  # So keep boot_wait short and spam Enter across the whole window instead.
  # Extra presses after the installer has started are harmless; it is already
  # reading autounattend.xml by then.
  boot_wait = "5s"
  boot_command = [
    "<enter><wait2><enter><wait2><enter><wait2><enter><wait2><enter>",
    "<wait2><enter><wait2><enter><wait2><enter><wait2><enter><wait2><enter>",
  ]
}

build {
  name    = "win11-analysis"
  sources = ["source.qemu.win11"]

  # Step 0: Stage the FakeNet config. 04-tools.ps1 moves it into
  # C:\Tools\FakeNet\configs\ once that directory exists; run_sample.py passes
  # it to fakenet -c at every detonation, so it has to be baked in here.
  # Destination is Temp because it is the one directory guaranteed to exist
  # before any provisioner has run.
  provisioner "file" {
    source      = "../config/fakenet.ini"
    destination = "C:/Windows/Temp/honeypot_fakenet.ini"
  }

  # ┌─ WHY THIS IS FOUR SCRIPTS AND NOT ONE ────────────────────────────────┐
  # │ FLARE-VM installs through Boxstarter, which reboots the guest an      │
  # │ unpredictable number of times and resumes via auto-login. Packer runs │
  # │ an elevated provisioner as a Windows scheduled task, so every one of  │
  # │ those reboots terminates the running task with 0x41306               │
  # │ (SCHED_S_TASK_TERMINATED), which Packer reports as                    │
  # │ "Script exited with non-zero exit status: 267014".                    │
  # │                                                                       │
  # │ With hardening, FLARE-VM and tooling in a single script that was      │
  # │ fatal: the 2026-07-31 14:27 build died after 30 minutes with          │
  # │ FLARE-VM's debloat.vm already installed, and the Sysmon/FakeNet/      │
  # │ Regshot phases never ran at all.                                      │
  # │                                                                       │
  # │ So: do the fast local work first (step 1), trigger FLARE-VM and let   │
  # │ go of it (step 2), absorb the reboots in bounded idempotent slices    │
  # │ (step 3, repeated), then install the tooling once the guest has       │
  # │ settled (step 4). 267014 is accepted wherever a reboot can land.      │
  # └───────────────────────────────────────────────────────────────────────┘

  # Step 1: hardening + Chocolatey. Fast, local, no reboots.
  provisioner "powershell" {
    script            = "scripts/01-hardening.ps1"
    elevated_user     = var.winrm_user
    elevated_password = var.winrm_pass
    timeout           = "30m"
  }

  # Step 2: trigger FLARE-VM and return. Boxstarter may reboot immediately, so
  # a terminated task here is a normal outcome, not a failure.
  provisioner "powershell" {
    script            = "scripts/02-flarevm-start.ps1"
    elevated_user     = var.winrm_user
    elevated_password = var.winrm_pass
    valid_exit_codes  = [0, 267014, 3010, 1641]
    timeout           = "30m"
  }

  # Step 3: eighteen 20-minute wait slices — a 6 h ceiling. Was twelve (4 h,
  # matching FLARE-VM's documented 2-4 h) until the 31 Jul 19:48 build: all
  # twelve slices ran out with FLARE-VM still actively installing (133
  # choco packages and climbing on the final slice, not stalled — the
  # completion marker is FLARE-VM's own metapackage folder under
  # chocolatey\lib\, which only appears once every dependency has already
  # resolved, so it's normal for the count to keep climbing right up until
  # it appears). 04-tools.ps1 then correctly refused to call that a golden
  # image (missing the RE toolkit) and exited 1, killing the whole build
  # after 4h16m of real, legitimate progress. Extended rather than loosening
  # 04-tools.ps1's own check — an image silently missing its toolkit is a
  # worse failure mode than a build that takes longer.
  # Each slice returns immediately once the completion
  # marker exists, so finishing early costs nothing but a few WinRM round
  # trips. A reboot simply ends the current slice and the next one picks up.
  # Not elevated: these only poll for a file, and a non-elevated provisioner
  # is not run as a scheduled task, so it has one less way to be killed.
  provisioner "powershell" {
    script = "scripts/03-flarevm-wait.ps1"
    # 1 is accepted here and ONLY here. 03-flarevm-wait.ps1 contains no
    # non-zero exit path — every branch ends in `exit 0` — so any non-zero
    # code from it means the run was interrupted, not that the script decided
    # something was wrong.
    #
    # Which code you get depends on how the provisioner runs. An elevated
    # provisioner is a scheduled task and returns 267014
    # (SCHED_S_TASK_TERMINATED) when a reboot kills it. These slices are
    # deliberately NOT elevated, so the command runs directly over WinRM and a
    # reboot mid-command surfaces as plain exit 1 instead. The 15:34 build died
    # on exactly that after 1h37m, with FLARE-VM 58 packages in: the earlier
    # fix covered the elevated code and not this one. 16001 is a third variant
    # of the same reboot-kill: the 31 Jul 18:10 slice hit it after polling a
    # full 1200s with no error, WinRM simply going EOF right as the script
    # tried to return - a reboot landing on the connection instead of a
    # scheduled task or a mid-command process.
    valid_exit_codes = [0, 1, 16001, 267014, 3010, 1641]
    timeout          = "40m"
  }
  provisioner "powershell" {
    script = "scripts/03-flarevm-wait.ps1"
    # 1 is accepted here and ONLY here. 03-flarevm-wait.ps1 contains no
    # non-zero exit path — every branch ends in `exit 0` — so any non-zero
    # code from it means the run was interrupted, not that the script decided
    # something was wrong.
    #
    # Which code you get depends on how the provisioner runs. An elevated
    # provisioner is a scheduled task and returns 267014
    # (SCHED_S_TASK_TERMINATED) when a reboot kills it. These slices are
    # deliberately NOT elevated, so the command runs directly over WinRM and a
    # reboot mid-command surfaces as plain exit 1 instead. The 15:34 build died
    # on exactly that after 1h37m, with FLARE-VM 58 packages in: the earlier
    # fix covered the elevated code and not this one. 16001 is a third variant
    # of the same reboot-kill: the 31 Jul 18:10 slice hit it after polling a
    # full 1200s with no error, WinRM simply going EOF right as the script
    # tried to return - a reboot landing on the connection instead of a
    # scheduled task or a mid-command process.
    valid_exit_codes = [0, 1, 16001, 267014, 3010, 1641]
    timeout          = "40m"
  }
  provisioner "powershell" {
    script = "scripts/03-flarevm-wait.ps1"
    # 1 is accepted here and ONLY here. 03-flarevm-wait.ps1 contains no
    # non-zero exit path — every branch ends in `exit 0` — so any non-zero
    # code from it means the run was interrupted, not that the script decided
    # something was wrong.
    #
    # Which code you get depends on how the provisioner runs. An elevated
    # provisioner is a scheduled task and returns 267014
    # (SCHED_S_TASK_TERMINATED) when a reboot kills it. These slices are
    # deliberately NOT elevated, so the command runs directly over WinRM and a
    # reboot mid-command surfaces as plain exit 1 instead. The 15:34 build died
    # on exactly that after 1h37m, with FLARE-VM 58 packages in: the earlier
    # fix covered the elevated code and not this one. 16001 is a third variant
    # of the same reboot-kill: the 31 Jul 18:10 slice hit it after polling a
    # full 1200s with no error, WinRM simply going EOF right as the script
    # tried to return - a reboot landing on the connection instead of a
    # scheduled task or a mid-command process.
    valid_exit_codes = [0, 1, 16001, 267014, 3010, 1641]
    timeout          = "40m"
  }
  provisioner "powershell" {
    script = "scripts/03-flarevm-wait.ps1"
    # 1 is accepted here and ONLY here. 03-flarevm-wait.ps1 contains no
    # non-zero exit path — every branch ends in `exit 0` — so any non-zero
    # code from it means the run was interrupted, not that the script decided
    # something was wrong.
    #
    # Which code you get depends on how the provisioner runs. An elevated
    # provisioner is a scheduled task and returns 267014
    # (SCHED_S_TASK_TERMINATED) when a reboot kills it. These slices are
    # deliberately NOT elevated, so the command runs directly over WinRM and a
    # reboot mid-command surfaces as plain exit 1 instead. The 15:34 build died
    # on exactly that after 1h37m, with FLARE-VM 58 packages in: the earlier
    # fix covered the elevated code and not this one. 16001 is a third variant
    # of the same reboot-kill: the 31 Jul 18:10 slice hit it after polling a
    # full 1200s with no error, WinRM simply going EOF right as the script
    # tried to return - a reboot landing on the connection instead of a
    # scheduled task or a mid-command process.
    valid_exit_codes = [0, 1, 16001, 267014, 3010, 1641]
    timeout          = "40m"
  }
  provisioner "powershell" {
    script = "scripts/03-flarevm-wait.ps1"
    # 1 is accepted here and ONLY here. 03-flarevm-wait.ps1 contains no
    # non-zero exit path — every branch ends in `exit 0` — so any non-zero
    # code from it means the run was interrupted, not that the script decided
    # something was wrong.
    #
    # Which code you get depends on how the provisioner runs. An elevated
    # provisioner is a scheduled task and returns 267014
    # (SCHED_S_TASK_TERMINATED) when a reboot kills it. These slices are
    # deliberately NOT elevated, so the command runs directly over WinRM and a
    # reboot mid-command surfaces as plain exit 1 instead. The 15:34 build died
    # on exactly that after 1h37m, with FLARE-VM 58 packages in: the earlier
    # fix covered the elevated code and not this one. 16001 is a third variant
    # of the same reboot-kill: the 31 Jul 18:10 slice hit it after polling a
    # full 1200s with no error, WinRM simply going EOF right as the script
    # tried to return - a reboot landing on the connection instead of a
    # scheduled task or a mid-command process.
    valid_exit_codes = [0, 1, 16001, 267014, 3010, 1641]
    timeout          = "40m"
  }
  provisioner "powershell" {
    script = "scripts/03-flarevm-wait.ps1"
    # 1 is accepted here and ONLY here. 03-flarevm-wait.ps1 contains no
    # non-zero exit path — every branch ends in `exit 0` — so any non-zero
    # code from it means the run was interrupted, not that the script decided
    # something was wrong.
    #
    # Which code you get depends on how the provisioner runs. An elevated
    # provisioner is a scheduled task and returns 267014
    # (SCHED_S_TASK_TERMINATED) when a reboot kills it. These slices are
    # deliberately NOT elevated, so the command runs directly over WinRM and a
    # reboot mid-command surfaces as plain exit 1 instead. The 15:34 build died
    # on exactly that after 1h37m, with FLARE-VM 58 packages in: the earlier
    # fix covered the elevated code and not this one. 16001 is a third variant
    # of the same reboot-kill: the 31 Jul 18:10 slice hit it after polling a
    # full 1200s with no error, WinRM simply going EOF right as the script
    # tried to return - a reboot landing on the connection instead of a
    # scheduled task or a mid-command process.
    valid_exit_codes = [0, 1, 16001, 267014, 3010, 1641]
    timeout          = "40m"
  }
  provisioner "powershell" {
    script = "scripts/03-flarevm-wait.ps1"
    # 1 is accepted here and ONLY here. 03-flarevm-wait.ps1 contains no
    # non-zero exit path — every branch ends in `exit 0` — so any non-zero
    # code from it means the run was interrupted, not that the script decided
    # something was wrong.
    #
    # Which code you get depends on how the provisioner runs. An elevated
    # provisioner is a scheduled task and returns 267014
    # (SCHED_S_TASK_TERMINATED) when a reboot kills it. These slices are
    # deliberately NOT elevated, so the command runs directly over WinRM and a
    # reboot mid-command surfaces as plain exit 1 instead. The 15:34 build died
    # on exactly that after 1h37m, with FLARE-VM 58 packages in: the earlier
    # fix covered the elevated code and not this one. 16001 is a third variant
    # of the same reboot-kill: the 31 Jul 18:10 slice hit it after polling a
    # full 1200s with no error, WinRM simply going EOF right as the script
    # tried to return - a reboot landing on the connection instead of a
    # scheduled task or a mid-command process.
    valid_exit_codes = [0, 1, 16001, 267014, 3010, 1641]
    timeout          = "40m"
  }
  provisioner "powershell" {
    script = "scripts/03-flarevm-wait.ps1"
    # 1 is accepted here and ONLY here. 03-flarevm-wait.ps1 contains no
    # non-zero exit path — every branch ends in `exit 0` — so any non-zero
    # code from it means the run was interrupted, not that the script decided
    # something was wrong.
    #
    # Which code you get depends on how the provisioner runs. An elevated
    # provisioner is a scheduled task and returns 267014
    # (SCHED_S_TASK_TERMINATED) when a reboot kills it. These slices are
    # deliberately NOT elevated, so the command runs directly over WinRM and a
    # reboot mid-command surfaces as plain exit 1 instead. The 15:34 build died
    # on exactly that after 1h37m, with FLARE-VM 58 packages in: the earlier
    # fix covered the elevated code and not this one. 16001 is a third variant
    # of the same reboot-kill: the 31 Jul 18:10 slice hit it after polling a
    # full 1200s with no error, WinRM simply going EOF right as the script
    # tried to return - a reboot landing on the connection instead of a
    # scheduled task or a mid-command process.
    valid_exit_codes = [0, 1, 16001, 267014, 3010, 1641]
    timeout          = "40m"
  }
  provisioner "powershell" {
    script = "scripts/03-flarevm-wait.ps1"
    # 1 is accepted here and ONLY here. 03-flarevm-wait.ps1 contains no
    # non-zero exit path — every branch ends in `exit 0` — so any non-zero
    # code from it means the run was interrupted, not that the script decided
    # something was wrong.
    #
    # Which code you get depends on how the provisioner runs. An elevated
    # provisioner is a scheduled task and returns 267014
    # (SCHED_S_TASK_TERMINATED) when a reboot kills it. These slices are
    # deliberately NOT elevated, so the command runs directly over WinRM and a
    # reboot mid-command surfaces as plain exit 1 instead. The 15:34 build died
    # on exactly that after 1h37m, with FLARE-VM 58 packages in: the earlier
    # fix covered the elevated code and not this one. 16001 is a third variant
    # of the same reboot-kill: the 31 Jul 18:10 slice hit it after polling a
    # full 1200s with no error, WinRM simply going EOF right as the script
    # tried to return - a reboot landing on the connection instead of a
    # scheduled task or a mid-command process.
    valid_exit_codes = [0, 1, 16001, 267014, 3010, 1641]
    timeout          = "40m"
  }
  provisioner "powershell" {
    script = "scripts/03-flarevm-wait.ps1"
    # 1 is accepted here and ONLY here. 03-flarevm-wait.ps1 contains no
    # non-zero exit path — every branch ends in `exit 0` — so any non-zero
    # code from it means the run was interrupted, not that the script decided
    # something was wrong.
    #
    # Which code you get depends on how the provisioner runs. An elevated
    # provisioner is a scheduled task and returns 267014
    # (SCHED_S_TASK_TERMINATED) when a reboot kills it. These slices are
    # deliberately NOT elevated, so the command runs directly over WinRM and a
    # reboot mid-command surfaces as plain exit 1 instead. The 15:34 build died
    # on exactly that after 1h37m, with FLARE-VM 58 packages in: the earlier
    # fix covered the elevated code and not this one. 16001 is a third variant
    # of the same reboot-kill: the 31 Jul 18:10 slice hit it after polling a
    # full 1200s with no error, WinRM simply going EOF right as the script
    # tried to return - a reboot landing on the connection instead of a
    # scheduled task or a mid-command process.
    valid_exit_codes = [0, 1, 16001, 267014, 3010, 1641]
    timeout          = "40m"
  }
  provisioner "powershell" {
    script = "scripts/03-flarevm-wait.ps1"
    # 1 is accepted here and ONLY here. 03-flarevm-wait.ps1 contains no
    # non-zero exit path — every branch ends in `exit 0` — so any non-zero
    # code from it means the run was interrupted, not that the script decided
    # something was wrong.
    #
    # Which code you get depends on how the provisioner runs. An elevated
    # provisioner is a scheduled task and returns 267014
    # (SCHED_S_TASK_TERMINATED) when a reboot kills it. These slices are
    # deliberately NOT elevated, so the command runs directly over WinRM and a
    # reboot mid-command surfaces as plain exit 1 instead. The 15:34 build died
    # on exactly that after 1h37m, with FLARE-VM 58 packages in: the earlier
    # fix covered the elevated code and not this one. 16001 is a third variant
    # of the same reboot-kill: the 31 Jul 18:10 slice hit it after polling a
    # full 1200s with no error, WinRM simply going EOF right as the script
    # tried to return - a reboot landing on the connection instead of a
    # scheduled task or a mid-command process.
    valid_exit_codes = [0, 1, 16001, 267014, 3010, 1641]
    timeout          = "40m"
  }
  provisioner "powershell" {
    script = "scripts/03-flarevm-wait.ps1"
    # 1 is accepted here and ONLY here. 03-flarevm-wait.ps1 contains no
    # non-zero exit path — every branch ends in `exit 0` — so any non-zero
    # code from it means the run was interrupted, not that the script decided
    # something was wrong.
    #
    # Which code you get depends on how the provisioner runs. An elevated
    # provisioner is a scheduled task and returns 267014
    # (SCHED_S_TASK_TERMINATED) when a reboot kills it. These slices are
    # deliberately NOT elevated, so the command runs directly over WinRM and a
    # reboot mid-command surfaces as plain exit 1 instead. The 15:34 build died
    # on exactly that after 1h37m, with FLARE-VM 58 packages in: the earlier
    # fix covered the elevated code and not this one. 16001 is a third variant
    # of the same reboot-kill: the 31 Jul 18:10 slice hit it after polling a
    # full 1200s with no error, WinRM simply going EOF right as the script
    # tried to return - a reboot landing on the connection instead of a
    # scheduled task or a mid-command process.
    valid_exit_codes = [0, 1, 16001, 267014, 3010, 1641]
    timeout          = "40m"
  }
  provisioner "powershell" {
    script = "scripts/03-flarevm-wait.ps1"
    # 1 is accepted here and ONLY here. 03-flarevm-wait.ps1 contains no
    # non-zero exit path — every branch ends in `exit 0` — so any non-zero
    # code from it means the run was interrupted, not that the script decided
    # something was wrong.
    #
    # Which code you get depends on how the provisioner runs. An elevated
    # provisioner is a scheduled task and returns 267014
    # (SCHED_S_TASK_TERMINATED) when a reboot kills it. These slices are
    # deliberately NOT elevated, so the command runs directly over WinRM and a
    # reboot mid-command surfaces as plain exit 1 instead. The 15:34 build died
    # on exactly that after 1h37m, with FLARE-VM 58 packages in: the earlier
    # fix covered the elevated code and not this one. 16001 is a third variant
    # of the same reboot-kill: the 31 Jul 18:10 slice hit it after polling a
    # full 1200s with no error, WinRM simply going EOF right as the script
    # tried to return - a reboot landing on the connection instead of a
    # scheduled task or a mid-command process.
    valid_exit_codes = [0, 1, 16001, 267014, 3010, 1641]
    timeout          = "40m"
  }
  provisioner "powershell" {
    script = "scripts/03-flarevm-wait.ps1"
    # 1 is accepted here and ONLY here. 03-flarevm-wait.ps1 contains no
    # non-zero exit path — every branch ends in `exit 0` — so any non-zero
    # code from it means the run was interrupted, not that the script decided
    # something was wrong.
    #
    # Which code you get depends on how the provisioner runs. An elevated
    # provisioner is a scheduled task and returns 267014
    # (SCHED_S_TASK_TERMINATED) when a reboot kills it. These slices are
    # deliberately NOT elevated, so the command runs directly over WinRM and a
    # reboot mid-command surfaces as plain exit 1 instead. The 15:34 build died
    # on exactly that after 1h37m, with FLARE-VM 58 packages in: the earlier
    # fix covered the elevated code and not this one. 16001 is a third variant
    # of the same reboot-kill: the 31 Jul 18:10 slice hit it after polling a
    # full 1200s with no error, WinRM simply going EOF right as the script
    # tried to return - a reboot landing on the connection instead of a
    # scheduled task or a mid-command process.
    valid_exit_codes = [0, 1, 16001, 267014, 3010, 1641]
    timeout          = "40m"
  }
  provisioner "powershell" {
    script = "scripts/03-flarevm-wait.ps1"
    # 1 is accepted here and ONLY here. 03-flarevm-wait.ps1 contains no
    # non-zero exit path — every branch ends in `exit 0` — so any non-zero
    # code from it means the run was interrupted, not that the script decided
    # something was wrong.
    #
    # Which code you get depends on how the provisioner runs. An elevated
    # provisioner is a scheduled task and returns 267014
    # (SCHED_S_TASK_TERMINATED) when a reboot kills it. These slices are
    # deliberately NOT elevated, so the command runs directly over WinRM and a
    # reboot mid-command surfaces as plain exit 1 instead. The 15:34 build died
    # on exactly that after 1h37m, with FLARE-VM 58 packages in: the earlier
    # fix covered the elevated code and not this one. 16001 is a third variant
    # of the same reboot-kill: the 31 Jul 18:10 slice hit it after polling a
    # full 1200s with no error, WinRM simply going EOF right as the script
    # tried to return - a reboot landing on the connection instead of a
    # scheduled task or a mid-command process.
    valid_exit_codes = [0, 1, 16001, 267014, 3010, 1641]
    timeout          = "40m"
  }
  provisioner "powershell" {
    script = "scripts/03-flarevm-wait.ps1"
    # 1 is accepted here and ONLY here. 03-flarevm-wait.ps1 contains no
    # non-zero exit path — every branch ends in `exit 0` — so any non-zero
    # code from it means the run was interrupted, not that the script decided
    # something was wrong.
    #
    # Which code you get depends on how the provisioner runs. An elevated
    # provisioner is a scheduled task and returns 267014
    # (SCHED_S_TASK_TERMINATED) when a reboot kills it. These slices are
    # deliberately NOT elevated, so the command runs directly over WinRM and a
    # reboot mid-command surfaces as plain exit 1 instead. The 15:34 build died
    # on exactly that after 1h37m, with FLARE-VM 58 packages in: the earlier
    # fix covered the elevated code and not this one. 16001 is a third variant
    # of the same reboot-kill: the 31 Jul 18:10 slice hit it after polling a
    # full 1200s with no error, WinRM simply going EOF right as the script
    # tried to return - a reboot landing on the connection instead of a
    # scheduled task or a mid-command process.
    valid_exit_codes = [0, 1, 16001, 267014, 3010, 1641]
    timeout          = "40m"
  }
  provisioner "powershell" {
    script = "scripts/03-flarevm-wait.ps1"
    # 1 is accepted here and ONLY here. 03-flarevm-wait.ps1 contains no
    # non-zero exit path — every branch ends in `exit 0` — so any non-zero
    # code from it means the run was interrupted, not that the script decided
    # something was wrong.
    #
    # Which code you get depends on how the provisioner runs. An elevated
    # provisioner is a scheduled task and returns 267014
    # (SCHED_S_TASK_TERMINATED) when a reboot kills it. These slices are
    # deliberately NOT elevated, so the command runs directly over WinRM and a
    # reboot mid-command surfaces as plain exit 1 instead. The 15:34 build died
    # on exactly that after 1h37m, with FLARE-VM 58 packages in: the earlier
    # fix covered the elevated code and not this one. 16001 is a third variant
    # of the same reboot-kill: the 31 Jul 18:10 slice hit it after polling a
    # full 1200s with no error, WinRM simply going EOF right as the script
    # tried to return - a reboot landing on the connection instead of a
    # scheduled task or a mid-command process.
    valid_exit_codes = [0, 1, 16001, 267014, 3010, 1641]
    timeout          = "40m"
  }
  provisioner "powershell" {
    script = "scripts/03-flarevm-wait.ps1"
    # 1 is accepted here and ONLY here. 03-flarevm-wait.ps1 contains no
    # non-zero exit path — every branch ends in `exit 0` — so any non-zero
    # code from it means the run was interrupted, not that the script decided
    # something was wrong.
    #
    # Which code you get depends on how the provisioner runs. An elevated
    # provisioner is a scheduled task and returns 267014
    # (SCHED_S_TASK_TERMINATED) when a reboot kills it. These slices are
    # deliberately NOT elevated, so the command runs directly over WinRM and a
    # reboot mid-command surfaces as plain exit 1 instead. The 15:34 build died
    # on exactly that after 1h37m, with FLARE-VM 58 packages in: the earlier
    # fix covered the elevated code and not this one. 16001 is a third variant
    # of the same reboot-kill: the 31 Jul 18:10 slice hit it after polling a
    # full 1200s with no error, WinRM simply going EOF right as the script
    # tried to return - a reboot landing on the connection instead of a
    # scheduled task or a mid-command process.
    valid_exit_codes = [0, 1, 16001, 267014, 3010, 1641]
    timeout          = "40m"
  }

  # Step 4: settle the guest before installing tooling. Boxstarter routinely
  # leaves a pending reboot behind, and Sysmon's driver install is not
  # something to attempt in that state.
  provisioner "windows-restart" {
    restart_timeout = "30m"
  }

  # Step 5: the analysis tooling run_sample.py actually depends on. Runs once,
  # after the reboots are over. Also records whether FLARE-VM made it.
  provisioner "powershell" {
    script            = "scripts/04-tools.ps1"
    elevated_user     = var.winrm_user
    elevated_password = var.winrm_pass
    timeout           = "60m"
  }

  # Step 6: final cleanup + sysprep-lite (do NOT full sysprep — breaks some tools)
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
