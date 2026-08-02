# win11-detnode-packer

Unattended Packer build of a Windows 11 "finance department" golden image on an
Ubuntu 26.04 KVM host, for use as a payload-detonation / malware-analysis box.

**Persona:** Michael Wilson (`mwilson`), Senior Financial Analyst – FP&A,
Meridian Capital Group. Machine `FIN-WS0147`, workgroup `CORPNET`, Dell
OptiPlex SMBIOS identity, EST timezone, aged filesystem artifacts, seeded
Chrome history, Outlook profile stub, mapped-drive shortcuts.

**Detonation plumbing:** FLARE FakeNet-NG (fake DNS/HTTP/HTTPS/SMTP/FTP/IRC +
corporate intranet landing page), Sysinternals, Wireshark, oletools/yara/pefile,
Defender sample submission disabled, SmartScreen off, autologon on.

## Layout

```
win11.pkr.hcl            Packer template (QEMU/KVM, UEFI, WinRM)
answer/autounattend.xml  Unattended install (TPM bypass, user, WinRM bootstrap)
provision/
  10-baseline.ps1        Power/telemetry/UAC/Defender/updates policy
  20-persona.ps1         Persona documents, timestamps, shortcuts, registry life
  30-tools.ps1           Chocolatey, Chrome, LibreOffice, Python, Sysinternals
  40-fakenet.ps1         FakeNet-NG install + startup scheduled task
  50-chrome-history.ps1  Seeds aged browsing history into Chrome's SQLite DB
  90-cleanup.ps1         Final cleanup (NO sysprep - clone qcow2 instead)
fakenet/detnode.ini      Tuned FakeNet config (fake finance intranet)
build.sh                 Host prep + packer build
detonate.sh              Create a throwaway overlay VM from the golden image
```

## Quick start

```bash
# 1. Put a Win11 ISO at /opt/iso/Win11_24H2_English_x64.iso (or set -var iso_url=...)
# 2. sha256sum the ISO and set -var iso_checksum=sha256:...
./build.sh

# Per detonation run (uses a qcow2 overlay; golden image stays pristine):
./detonate.sh run1
# ... boot, FakeNet is already running, detonate payload, kill VM, delete overlay
```

## Notes / caveats

- **No sysprep.** Sysprep would destroy the persona. Clone via qcow2 backing
  files. If you ever need SIDs regenerated, use `sysprep /generalize` on a
  *copy* and accept persona loss.
- **Password** defaults to `P@ssw0rd!Fin` in three places (autounattend base64,
  Packer var, WinRM). Rotate all three. Regenerate the base64 with:
  `[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('NEWPASS'+'Password'))`
- **OVMF path** varies by distro; check `/usr/share/OVMF/` if the build errors
  on firmware.
- **Win11 ISO edition name**: the answer file selects "Windows 11 Pro". Verify
  against your ISO (`dism /Get-WimInfo /WimFile:install.wim` equivalents) and
  adjust `/IMAGE/NAME` if needed.
- **KMS key** in the answer file is Microsoft's public, non-activating GVLK —
  replace with your own licensing.
- Real MS Office: drop an ODT `odt-config.xml` into `C:\ProgramData\persona\`
  during build (see 30-tools.ps1) — otherwise LibreOffice stands in.
- This is an **analysis host**: Defender sample submission and SmartScreen are
  off, firewall is off, autologon is on. Never expose its network. Run it on an
  isolated libvirt network; FakeNet answers everything locally.

## Hardening the illusion (optional, manual)

- `pafish` / `al-khaser` inside the guest show remaining VM tells.
- virtio drivers still leak; for high-bar samples consider passthrough GPU/NIC
  or at least rename QEMU devices via libvirt XML.
- Generate real .docx/.xlsx with python-docx/openpyxl seeded with content and
  aged timestamps — text placeholders only survive shallow triage.
