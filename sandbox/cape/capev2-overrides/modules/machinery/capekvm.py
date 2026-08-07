# capekvm.py -- KVM machinery variant for guests whose CPU model is
# migratable='off' (full host-passthrough CPU exposure, for anti-detection
# realism -- see sandbox/cape/win11-cape-kvm.xml's own header) and
# therefore cannot use the running-state libvirt snapshot the stock
# modules/machinery/kvm.py module requires. LibVirtMachinery.start()
# always calls vm.revertToSnapshot(), which needs a full memory+disk
# snapshot -- confirmed live (2026-08-07) failing against win11-cape with
# "cannot migrate domain: State blocked by non-migratable CPU device
# (invtsc flag)": QEMU/libvirt snapshot save/restore reuses the same
# migration machinery live migration does, and migratable='off' blocks it
# outright regardless of source and destination being the same host.
#
# Same revert strategy sandbox/windows's own orchestrator already uses for
# win11-sandbox, for the identical underlying reason (see that domain's
# own win11-kvm.xml header): destroy the domain, throw away its overlay
# disk, recreate a fresh thin qcow2 overlay from the golden image, then a
# plain vm.create() -- no snapshot involved at any point. This also means
# the golden image's own single-use unattend.xml AutoLogon fires fresh on
# every single analysis: each new overlay's first boot IS that overlay's
# first boot, reading the SAME pristine (never-logged-in-from-its-own-
# perspective) base state off the read-only golden image every time.
#
# golden_image / vm_disk are read from this module's own conf file
# (conf/capekvm.conf's per-machine section), not hardcoded here, so they
# stay in one place alongside every other machine-specific setting.
import logging
import os
import subprocess
import xml.etree.ElementTree as ET

import libvirt

from lib.cuckoo.common.abstracts import LibVirtMachinery
from lib.cuckoo.common.exceptions import CuckooMachineError

log = logging.getLogger(__name__)


class CapeKVM(LibVirtMachinery):
    """Virtualization layer for KVM guests that can't use libvirt snapshots."""

    module_name = "capekvm"

    def _initialize_check(self):
        if not self.options.capekvm.dsn:
            raise CuckooMachineError("KVM DSN is missing, please add it to the config file")
        self.dsn = self.options.capekvm.dsn
        super()._initialize_check()

    def _get_interface(self, label):
        xml = ET.fromstring(self._lookup(label).XMLDesc())
        elem = xml.find("./devices/interface[@type='network']")
        if elem is None:
            return None
        elem = elem.find("target")
        if elem is None:
            return None
        return elem.attrib["dev"]

    def _machine_opts_for_label(self, label):
        mmanager_opts = self.options.get(self.module_name)
        for machine_id in mmanager_opts["machines"]:
            machine_id = machine_id.strip()
            candidate = self.options.get(machine_id)
            if candidate.get("label") == label:
                return candidate
        raise CuckooMachineError(f"No capekvm machine configuration found for label {label}")

    def start(self, label=None):
        if not label:
            raise CuckooMachineError("Machine label required")

        log.debug("Starting machine %s", label)

        vm_info = self.db.view_machine_by_label(label)
        if vm_info is None:
            raise CuckooMachineError(f"Unable to find machine with label {label} in database.")

        if self._status(label) != self.POWEROFF:
            raise CuckooMachineError(f"Trying to start a virtual machine that has not been turned off {label}")

        # `label` here is the libvirt domain label (e.g. "win11-cape"), NOT
        # the config section id (e.g. "cuckoo1") -- machinery_manager.py
        # calls `self.machinery.start(machine.label)`, and this repo's own
        # capekvm.conf deliberately gives the config section a short id
        # distinct from its (more descriptive) `label =` value, the same
        # way kvm.conf's own stock template already does for its "cuckoo1"
        # example. Found live (2026-08-07): `self.options.get(label)`
        # looked up a config section literally named "win11-cape", which
        # doesn't exist, raising CuckooOperationalError and failing every
        # task before the VM ever started. The config section has to be
        # found by matching its own `label =` value instead.
        machine_opts = self._machine_opts_for_label(label)
        golden_image = machine_opts.get("golden_image")
        vm_disk = machine_opts.get("vm_disk")
        if not golden_image or not vm_disk:
            raise CuckooMachineError(
                f"capekvm requires golden_image and vm_disk to be set in conf/capekvm.conf for machine label {label}"
            )
        if not os.path.exists(golden_image):
            raise CuckooMachineError(f"golden_image not found for {label}: {golden_image}")

        if os.path.exists(vm_disk):
            os.remove(vm_disk)
        try:
            subprocess.run(
                ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", golden_image, vm_disk],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as e:
            raise CuckooMachineError(f"Unable to recreate overlay disk for {label}: {e.stderr}") from e

        conn = self._connect(label)
        try:
            vm = conn.lookupByName(label)
            vm.create()
        except libvirt.libvirtError as e:
            raise CuckooMachineError(f"Unable to start virtual machine {label}: {e}") from e

        self._wait_status(label, self.RUNNING)

        machine = self.db.view_machine_by_label(label)
        if machine:
            iface = getattr(machine, "interface", self._get_interface(label))
            if iface:
                self.db.set_machine_interface(label, iface)
            else:
                log.warning("Can't get iface for %s", label)

    def store_vnc_port(self, label: str, task_id: int):
        xml = ET.fromstring(self._lookup(label).XMLDesc())
        graphics = xml.find("./devices/graphics")
        if graphics is not None:
            port = int(graphics.get("port", -1))
            if port > 0:
                self.db.set_vnc_port(task_id, port)
                return

        log.warning("Can't get VNC port for %s", label)
