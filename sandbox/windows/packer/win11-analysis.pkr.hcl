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
# Prefer build-with-retry.sh <checksum> [max_attempts] over calling `packer
# build` directly: packer's WinRM communicator treats some transport errors
# (a "401 - invalid content type" mid-poll response, seen after 4h20m of
# otherwise-healthy progress on 2026-08-01, #194) as fatal on the first
# occurrence despite logging them with the same "Retryable error:" prefix
# used for errors it does retry. There is no packer-level knob for this --
# winrm_timeout below only governs the initial connect wait -- so the retry
# lives one level up, around the whole build.
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
  # 12 of the host's 16 threads, bumped from 8 to speed up install --
  # Windows Setup's file-copy/component-install phases parallelize well.
  # Leaves 4 threads for the honeypot stack running alongside; revisit if
  # that starves under load.
  default = "12"
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

  # UEFI, Secure Boot OFF for now -- TEMPORARY, see #288/#419. The
  # cert-signed approach (pxe/prepare-pxe.sh: self-generated cert, sbsign,
  # OVMF_VARS_4M.honeypot-pxe.fd with that cert + Microsoft's win11 certs
  # both enrolled in db) is built and confirmed working standalone -- signed
  # ipxe.efi boots clean under full Secure Boot enforcement, and a
  # negative-control boot of the unsigned binary against the same vars file
  # is correctly rejected. But the one real packer-driven build attempted
  # under it failed differently than every non-secboot run tonight: PXE
  # succeeded initially (confirmed via screenshot: wimboot/BCD/BOOT.SDI ok,
  # boot.wim streaming), then the guest reset and fell through firmware's
  # boot order to the CD-boot-prompt path (which has no boot_command
  # anymore) and then to an empty disk, landing at "No bootable option or
  # device was found" -- qcow2 never grew past its initial allocation.
  # Not yet root-caused whether that's secure-boot-specific (bootmgfw doing
  # its own additional validation once handed off from wimboot) or
  # coincidental flakiness, since every prior run tonight (all non-secboot)
  # reached this exact stage reliably. Reverting to non-secboot to get a
  # working golden image first; re-enable once the reset is understood
  # rather than guessing again under time pressure. The efi_firmware_* lines
  # below and pxe/OVMF_VARS_4M.honeypot-pxe.fd are both ready to swap back
  # in unchanged when that happens.
  #
  # This was the earlier install-time-only compromise: Windows 11 setup
  # itself only needs UEFI (Secure Boot's *check* is bypassed via the
  # LabConfig registry keys in autounattend.xml regardless), and the final
  # win11-kvm.xml detonation domain is unaffected either way -- the
  # installed Windows Boot Manager is itself Microsoft-signed and boots
  # fine under Secure Boot even though it wasn't installed under it.
  efi_boot          = true
  efi_firmware_code = "/usr/share/OVMF/OVMF_CODE_4M.fd"
  efi_firmware_vars = "/usr/share/OVMF/OVMF_VARS_4M.fd"

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

  # Fixed VNC port (not packer's default auto-picked-from-a-range) so a
  # relay/monitor script can point at one stable address across attempts
  # instead of re-discovering the port every time.
  vnc_port_min = 5999
  vnc_port_max = 5999

  # PXE boot instead of CD-ROM boot (#288, #406).
  #
  # The old approach raced "Press any key to boot from CD or DVD" via VNC
  # keystroke injection (spacebar spam, see git history for the full
  # 50d12e4/89a516d/d14b1e0/0ae41a2 investigation this replaces). Confirmed
  # live over a full night of builds: it missed far more often than it hit,
  # repeatedly leaving the guest stuck at BdsDxe "No bootable option or
  # device was found" with a qcow2 that never grows past its initial
  # allocation. That is a structurally flaky mechanism -- a keystroke has
  # to land inside a ~5s window that only starts after OVMF's own
  # unpredictable init time -- not a tunable one.
  #
  # PXE boot has no such prompt: the firmware loads a network boot program
  # and goes. This second NIC exists solely to boot from; the WinRM
  # communicator still uses packer's own auto-created NIC (net0/user.0,
  # with its hostfwd) exactly as before, unaffected by this one being
  # present. See pxe/prepare-pxe.sh for what's being served here and why
  # (OVMF requires a real signed-shape PE32+ EFI executable as the PXE boot
  # file, not a raw iPXE script, and a stock ipxe.efi's autoboot loops
  # forever instead of ever reaching a fetched script -- both confirmed
  # live -- so ipxe.efi is custom-built there with the wimboot chainload
  # script embedded at compile time).
  #
  # autounattend.xml still applies exactly as before: Windows Setup scans
  # all attached media for it regardless of how WinPE itself was booted,
  # so cd_files above is unchanged.
  #
  # qemuargs REPLACES packer's own generated qemu args entirely rather than
  # appending to them -- confirmed live: without explicitly re-adding
  # user.0/hostfwd here, the WinRM communicator's NIC silently vanished
  # from the qemu command line. So both NICs are listed explicitly: user.0
  # is exactly what packer would have generated on its own (hostfwd to the
  # communicator port, via the {{ .SSHHostPort }} template var packer
  # exposes to qemuargs -- named for SSH historically, used for WinRM here
  # same as everywhere else in this communicator), and pxenet0 is the
  # PXE-only NIC.
  #
  # Two more bugs found chasing the boot-order fix, both confirmed live:
  #
  # 1. `-boot once=n,order=c` (tried as the "network once, disk afterward"
  #    fix) turned out to be a no-op -- this OVMF build doesn't implement
  #    the legacy `-boot` compatibility shim at all. The boot log with it
  #    set showed the plain default NVRAM order (CD, CD, HARDDISK, PXE
  #    last), not network-first. bootindex is the mechanism this OVMF
  #    actually honors (confirmed repeatedly tonight), so that's back --
  #    but bootindex alone re-triggers PXE on *every* guest-initiated
  #    restart forever, which is the infinite-reinstall loop this was
  #    meant to fix in the first place. Solved below by unplugging pxenet0
  #    via QMP the moment the first guest reset happens, instead of trying
  #    to make a boot-order flag do something it structurally can't (a
  #    static boot order can't distinguish "first boot" from "the guest
  #    reset itself" -- both are just "the VM is booting" to the firmware).
  #
  # 2. Two `-netdev user` instances default to the *same* internal subnet
  #    (10.0.2.0/24) and silently collide -- confirmed live, BdsDxe's PXE
  #    attempt landed on user.0 (MAC ...56, no tftp config at all) instead
  #    of pxenet0 (MAC ...57) and failed DHCP with "No valid offer
  #    received". Each needs its own `net=`/`dhcpstart=` range.
  #
  # QMP (unix socket, fixed path so pxe/unplug-pxe-on-reset.sh can find it
  # without scraping qemu's own stdout) is what makes the reset-triggered
  # unplug possible: it emits a RESET event the instant the guest asks for
  # one, before firmware even starts re-enumerating boot options for that
  # next boot.
  qemuargs = [
    ["-qmp", "unix:/tmp/win11-analysis-qmp.sock,server,nowait"],
    # id=pxenet0dev on the *device* (not just the netdev backend) is
    # required for device_del to find anything -- confirmed live, without
    # it QEMU auto-generates an anonymous device id and
    # `device_del pxenet0` fails with "Device 'pxenet0' not found" even
    # though the netdev backend really is named pxenet0. device_del
    # operates on the qdev/PCI device id, which is a separate namespace
    # from netdev backend ids.
    ["-device", "e1000e,netdev=pxenet0,bootindex=1,id=pxenet0dev"],
    ["-netdev", "user,id=pxenet0,net=10.0.2.0/24,dhcpstart=10.0.2.15,tftp=pxe,bootfile=ipxe.efi"],
    ["-device", "e1000e,netdev=user.0"],
    ["-netdev", "user,id=user.0,net=10.0.3.0/24,dhcpstart=10.0.3.15,hostfwd=tcp::{{ .SSHHostPort }}-:5985"],
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

  # #294: the fake-intranet landing page FakeNet's HTTP/HTTPS listeners
  # serve as their DefaultFiles -- staged the same way as the ini itself,
  # moved into place by 04-tools.ps1 alongside it.
  provisioner "file" {
    source      = "../config/defaultFiles"
    destination = "C:/Windows/Temp/honeypot_fakenet_defaultFiles"
  }

  # FLARE-VM (Mandiant's 100+ tool RE distribution) was here through
  # 2026-08-02 and is deliberately gone now: run_sample.py's automated
  # detonation pipeline never called any tool FLARE-VM uniquely provided --
  # Procmon (SysinternalsSuite), Regshot, and FakeNet are all installed
  # independently below, in 04-tools.ps1. FLARE-VM's own Boxstarter installer
  # was also the source of nearly every build failure this template has ever
  # hit (repeated unpredictable reboots, multi-hour installs, transient WinRM
  # drops mid-install) for a toolset (disassemblers, debuggers) only useful
  # for manual investigation this pipeline doesn't do. See the git history of
  # this file for the multi-script reboot-slicing structure FLARE-VM required,
  # if that manual-investigation tooling is ever wanted back.

  # Step 1: hardening + Chocolatey. Fast, local, no reboots.
  provisioner "powershell" {
    script            = "scripts/01-hardening.ps1"
    elevated_user     = var.winrm_user
    elevated_password = var.winrm_pass
    timeout           = "30m"
  }

  # Step 2: settle the guest before installing tooling. Cheap insurance
  # against a pending reboot from 01-hardening.ps1 or Windows itself --
  # Sysmon's driver install is not something to attempt in that state. No
  # longer load-bearing the way it was for Boxstarter's routine reboots, but
  # harmless and fast, so left in rather than removed.
  provisioner "windows-restart" {
    restart_timeout = "30m"
  }

  # Step 3: the analysis tooling run_sample.py actually depends on. Runs once,
  # after the settle-restart above.
  provisioner "powershell" {
    script            = "scripts/04-tools.ps1"
    elevated_user     = var.winrm_user
    elevated_password = var.winrm_pass
    timeout           = "60m"
  }

  # Step 3b: VC++ Redistributable (#368) -- without it, natively-compiled C++
  # samples fail to launch at all (STATUS_DLL_NOT_FOUND), which reads in a
  # detonation report as "did nothing interesting" rather than "couldn't
  # start." Core to the sandbox's actual purpose, not cosmetic; placed right
  # after the real tooling step for the same reason.
  provisioner "powershell" {
    script            = "scripts/09-vcredist.ps1"
    elevated_user     = var.winrm_user
    elevated_password = var.winrm_pass
    timeout           = "15m"
  }

  # Step 3c: LOLDrivers BYOVD bait -- a curated set of known-vulnerable,
  # signed kernel drivers dropped onto disk, plus disabling the Microsoft
  # Vulnerable Driver Blocklist so a sample that tries to abuse one of them
  # for privesc/EDR-kill actually can, and gets observed doing it. Analysis
  # image only -- never win11-ghosts (see script header and #467).
  provisioner "powershell" {
    script            = "scripts/10-loldrivers.ps1"
    elevated_user     = var.winrm_user
    elevated_password = var.winrm_pass
    timeout           = "10m"
  }

  # Step 4: decoy realism -- sample documents and a local SMB share, so the
  # guest reads as a real workstation rather than a bare analysis box to
  # anyone who lands on it. Independent of the tooling above; safe to skip
  # or extend without touching run_sample.py's dependencies.
  provisioner "powershell" {
    script            = "scripts/05-decoy-content.ps1"
    elevated_user     = var.winrm_user
    elevated_password = var.winrm_pass
    timeout           = "15m"
  }

  # Step 5: Chrome browsing history seeding (#292). Installs Chrome/Python if
  # needed, then seeds aged history rows straight into the SQLite DB so the
  # profile isn't empty/default -- a T1497.002 check. Independent of
  # 05-decoy-content.ps1's filesystem artifacts; only shares the persona
  # identity #293 settled on.
  provisioner "powershell" {
    script            = "scripts/06-chrome-history.ps1"
    elevated_user     = var.winrm_user
    elevated_password = var.winrm_pass
    timeout           = "20m"
  }

  # Step 6: living-persona daemon + background traffic noise (#290, #291).
  # Registers two hidden AtLogOn scheduled tasks: one simulates human
  # mouse/keyboard/scroll activity, the other issues background DNS/HTTP(S)
  # noise tagged for later pcap filtering. Both need an interactive desktop
  # session to actually do anything -- they only *register* here, run_sample.py's
  # virsh boot + autologon flow is what gives them one.
  provisioner "powershell" {
    script            = "scripts/07-living-persona.ps1"
    elevated_user     = var.winrm_user
    elevated_password = var.winrm_pass
    timeout           = "10m"
  }

  provisioner "powershell" {
    script            = "scripts/08-traffic-noise.ps1"
    elevated_user     = var.winrm_user
    elevated_password = var.winrm_pass
    timeout           = "10m"
  }

  # Step 7: final cleanup + sysprep-lite (do NOT full sysprep — breaks some tools)
  #
  # This step is best-effort housekeeping only -- nothing here should ever be
  # able to fail a build that has already done real work. Confirmed live (in
  # the earlier FLARE-VM-based version of this template, kept here as an
  # accurate historical record even though the specific "FLARE-VM package
  # retry" cause below no longer applies post-removal): it did exactly that.
  # `wevtutil cl` is a native exe, not a cmdlet, so
  # `-ErrorAction SilentlyContinue` (which only affects cmdlets) does nothing
  # for it -- and PowerShell's $LastExitCode only updates on a native-command
  # invocation, so whatever `wevtutil` last returned silently became the
  # WHOLE PROVISIONER's exit code once packer's execute_command wrapper ran
  # `exit $LastExitCode`, even though every later cmdlet in this block
  # (Remove-Item, WriteAllText, Write-Output) succeeded. One run had Sysmon
  # not actually installed (a FLARE-VM package retry could legitimately
  # leave it missing, back when FLARE-VM was part of this build), so
  # `wevtutil cl Microsoft-Windows-Sysmon/Operational` failed with "channel
  # not found", that exit code rode untouched through the rest of the
  # script, and packer marked "Build ... errored after 6 hours 26 minutes"
  # and deleted the entire output directory -- despite setup, FLARE-VM, and
  # the decoy environment having all completed successfully. Each native
  # call is now wrapped to force $LASTEXITCODE
  # back to 0 regardless of outcome, and the block ends on an explicit
  # `exit 0` as a second line of defense against any future best-effort step
  # added here doing the same thing.
  provisioner "powershell" {
    inline = [
      # DNS-to-INetSim (10.10.10.1): moved here from 04-tools.ps1's old
      # Phase 13 (#432) -- that script assumed it was the last provisioner,
      # which stopped being true once 06-chrome-history.ps1 was added after
      # it and needed real internet for its own Chrome download. This step
      # actually is guaranteed last regardless of what else gets added to
      # the provisioner chain before it.
      #
      # Deliberately belt-and-braces: setup/sandbox-network.xml already
      # hands out 10.10.10.1 via dhcp-option=6, and this survives a guest
      # that somehow misses the DHCP option. The cost is that 10.10.10.1 is
      # now written down in three places -- here, that file, and the
      # inetsim ipv4_address in docker-compose.sandbox.yml. All three are
      # pinned constants; change one and you must change all three, or the
      # static entry here will silently win over DHCP and every lookup will
      # go to a dead address.
      "$adapter = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1; Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses '10.10.10.1'",
      # Clear event logs (start fresh for analysis)
      "Get-EventLog -List | ForEach-Object { Clear-EventLog -LogName $_.Log -ErrorAction SilentlyContinue }",
      "wevtutil cl Microsoft-Windows-Sysmon/Operational 2>$null; $global:LASTEXITCODE = 0",
      "wevtutil cl Microsoft-Windows-PowerShell/Operational 2>$null; $global:LASTEXITCODE = 0",
      # Clear temp files
      "Remove-Item -Recurse -Force C:\\Windows\\Temp\\* -ErrorAction SilentlyContinue",
      "Remove-Item -Recurse -Force C:\\Users\\analyst\\AppData\\Local\\Temp\\* -ErrorAction SilentlyContinue",
      # Mark build timestamp
      "[System.IO.File]::WriteAllText('C:\\golden_image_build.txt', (Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'))",
      "Write-Output 'Golden image build complete'",
      "exit 0"
    ]
  }
}
