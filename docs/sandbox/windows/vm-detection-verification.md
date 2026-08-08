# Post-build VM detection verification (#298)

`win11-analysis.pkr.hcl` and `win11-kvm.xml` are both extensively commented
with *why* each anti-detection setting was chosen (SMBIOS/CPUID/disk-serial/
NIC spoofing, Defender/telemetry/UAC disables). That reasoning is necessarily
a checklist against *known* checks. The only way to find out what's actually
still detectable in the built guest is to run real detection tools inside it:
[pafish](https://github.com/a0rtega/pafish) and
[al-khaser](https://github.com/LordNoteworthy/al-khaser).

**Status: blocked on the golden image existing** (#47 and its sub-issues,
same as most of Phases 1-3). `orchestrate/verify_vm_detection.py` is written
and ready to run the moment a `win11-sandbox` domain exists — nothing here
is blocked beyond that. (There is no `GOLDEN_READY` snapshot to wait on —
see #358 for why the revert mechanism is a fresh CoW clone, not a virsh
snapshot.)

## Why this matters

The settings in `win11-kvm.xml` and the provisioner scripts could be
individually correct and still miss something only visible once they're all
combined in a booted guest — e.g. a value one provisioner script sets getting
reset by a later one, or a tell nobody thought to hard-code a fix for.
`RESEARCH.md` §1.2 (from the `windows_kimi` prototype this verification pass
was scoped from) calls out specific residual tells worth checking even after
everything currently hardened is applied:

- **rdtsc-forced VM-exit timing** — no reliable KVM fix exists; this is the
  hardest one and may simply have to be accepted as a known gap.
- **Remaining virtio driver names** anywhere in the guest (AHCI/e1000e were
  chosen over virtio-blk/virtio-net specifically to avoid this, but a
  leftover virtio-serial channel for the QEMU guest agent, or an unexpected
  virtio-balloon device, is worth confirming absent).
- **Screen resolution** — should read as 1920x1080, not a default headless
  size.
- **System uptime** at analysis time.

## Running it

1. Obtain `pafish.exe` and `al-khaser.exe` on the analysis host (build from
   source or download a release — they never touch the internet from inside
   the guest; FakeNet/INetSim would just answer whatever they ask anyway).
2. Boot a fresh clone of the golden image, the same way
   `orchestrate/run_sample.py`'s `revert_to_golden()` does.
3. Run:
   ```bash
   python3 orchestrate/verify_vm_detection.py \
     --pafish /path/to/pafish.exe --al-khaser /path/to/al-khaser.exe
   ```
4. The script pushes each tool to `C:\Inbox`, runs it over WinRM, and
   writes a timestamped Markdown report to `docs/sandbox/windows/vm-detection-results/`
   containing both tools' full output plus the three residual-tell checks
   above. **Commit the report** — this is the durable, checked-in record
   that verification actually happened, matching the pattern
   `04-tools.ps1` already uses for `C:\golden_image_provenance.txt` inside
   the image itself.

## When to re-run

Re-run after every golden-image rebuild (see #86's scheduled-rebuild issue)
and after any change to `win11-kvm.xml`, `packer/scripts/01-hardening.ps1`,
or the QEMU/libvirt hardware identity — a later provisioner change or a host
package upgrade can silently reintroduce a tell an earlier script fixed.

## Ideally: fold into the golden-image acceptance gate

Per the issue this was scoped from, the long-term goal is to make this part
of the same acceptance check that gates trusting a freshly-built golden
image (`IMPLEMENTATION_PLAN.md` Phase 2), not a separate manual step
someone has to remember to run. That wiring is left for whoever builds the
image in #47 — this doc and script are the verification half; the
"must pass before the image is trusted" gate is a Phase 2 process decision,
not a script that can be written against an image that doesn't exist yet.
