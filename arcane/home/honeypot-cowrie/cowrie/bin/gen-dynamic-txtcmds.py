#!/usr/bin/env python3
"""Generate randomised-but-plausible txtcmd output files.

Covers:
  dynamic system state  : free, df, ss, top, w, uptime, lscpu, nproc,
                           last, lastlog
  hardware identity     : /proc/version, /proc/cpuinfo, /proc/meminfo

All generators share a single SimState so values are internally
consistent across commands within the same container boot.

Run once at container startup (entrypoint / docker-entrypoint.sh).

Usage:
    gen-dynamic-txtcmds.py <txtcmds_root>
"""
import os
import sys
import random
import math
import datetime
from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# Shared simulated state — one coherent snapshot of the machine
# ---------------------------------------------------------------------------

@dataclass
class SimState:
    # Uptime: between 10 and 90 days
    uptime_days:   int   = field(default_factory=lambda: random.randint(10, 90))
    uptime_hours:  int   = field(default_factory=lambda: random.randint(0, 23))
    uptime_mins:   int   = field(default_factory=lambda: random.randint(0, 59))

    # Load average — realistic for a busy ML node (mostly GPU, some CPU)
    load1:         float = field(default_factory=lambda: round(random.uniform(1.8, 4.2), 2))
    load5:         float = field(default_factory=lambda: round(random.uniform(1.6, 3.8), 2))
    load15:        float = field(default_factory=lambda: round(random.uniform(1.4, 3.4), 2))

    # CPU utilisation — split across 128 logical cores
    cpu_us:        float = field(default_factory=lambda: round(random.uniform(1.2, 3.8), 1))
    cpu_sy:        float = field(default_factory=lambda: round(random.uniform(0.2, 0.8), 1))
    cpu_wa:        float = field(default_factory=lambda: round(random.uniform(0.0, 0.3), 1))

    # Memory (kB) — 512 GB physical
    mem_total_kb:  int   = 527_869_952
    swap_total_kb: int   = 33_554_432

    def __post_init__(self):
        used_pct      = random.uniform(0.18, 0.55)
        self.mem_used_kb  = int(self.mem_total_kb * used_pct)
        bc_pct            = random.uniform(0.30, 0.55)
        self.mem_bc_kb    = int(self.mem_total_kb * bc_pct)
        if self.mem_used_kb + self.mem_bc_kb > self.mem_total_kb - 4096:
            self.mem_bc_kb = self.mem_total_kb - self.mem_used_kb - 4096
        self.mem_free_kb  = self.mem_total_kb - self.mem_used_kb - self.mem_bc_kb
        self.mem_avail_kb = self.mem_bc_kb + self.mem_free_kb - random.randint(0, 2_097_152)

        self.cpu_id   = round(100.0 - self.cpu_us - self.cpu_sy - self.cpu_wa
                              - round(random.uniform(0.0, 0.2), 1), 1)
        self.cpu_hi   = round(random.uniform(0.0, 0.1), 1)
        self.cpu_si   = round(random.uniform(0.0, 0.2), 1)
        self.cpu_ni   = 0.0
        self.cpu_st   = 0.0

        # Wall-clock time of the session (current UTC time as far as the guest knows)
        now = datetime.datetime.utcnow()
        self.now = now
        self.time_str  = now.strftime("%H:%M:%S")
        self.date_str  = now.strftime("%a %b %d")

        # Uptime string, e.g. "47 days, 14:22"
        self.uptime_str = f"{self.uptime_days} days, {self.uptime_hours:02d}:{self.uptime_mins:02d}"

        # Simulated login-from IP (management subnet)
        self.mgmt_ip = f"10.0.0.{random.randint(10, 20)}"

        # Login hour — a few hours before "now"
        login_hour = (now.hour - random.randint(1, 4)) % 24
        self.login_time_str = f"{login_hour:02d}:{random.randint(0,59):02d}"

        # Hugepage pool — counts are PAGES (2048 kB each, see Hugepagesize).
        # Provisioned-but-modest, as for a sysctl vm.nr_hugepages setting;
        # must stay far below MemTotal so meminfo cannot contradict itself.
        # (#2108: the old constant was 2**30 mislabeled as kB, i.e. a 1 TiB
        # pool on a 512 GB machine.)
        self.hugepage_pages      = _r(4096, 10)
        self.hugepage_free_pages = random.randint(self.hugepage_pages // 4,
                                                  self.hugepage_pages)


def _r(base: int, jitter_pct: float) -> int:
    delta = int(base * jitter_pct / 100)
    return base + random.randint(-delta, delta)


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


# ---------------------------------------------------------------------------
# /proc identity files
# ---------------------------------------------------------------------------

def gen_proc_files(out_dir: Path, s: SimState) -> None:
    _write(out_dir / "proc" / "version",
        "Linux version 5.15.0-119-generic "
        "(buildd@lcy02-amd64-055) "
        "(gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, "
        "GNU ld (GNU Binutils for Ubuntu) 2.38) "
        "#129-Ubuntu SMP Fri Aug 2 19:25:20 UTC 2024\n")

    cpu_lines = []
    for cpu_id in range(128):
        mhz      = round(random.uniform(1499.8, 2249.9), 3)
        bogomips = round(mhz * 2, 2)
        socket   = 0 if cpu_id < 64 else 1
        core_id  = cpu_id % 64
        cpu_lines.append(
            f"processor\t: {cpu_id}\n"
            f"vendor_id\t: AuthenticAMD\n"
            f"cpu family\t: 23\n"
            f"model\t\t: 49\n"
            f"model name\t: AMD EPYC 7742 64-Core Processor\n"
            f"stepping\t: 0\n"
            f"microcode\t: 0x8301038\n"
            f"cpu MHz\t\t: {mhz}\n"
            f"cache size\t: 512 KB\n"
            f"physical id\t: {socket}\n"
            f"siblings\t: 128\n"
            f"core id\t\t: {core_id}\n"
            f"cpu cores\t: 64\n"
            f"apicid\t\t: {cpu_id * 2}\n"
            f"initial apicid\t: {cpu_id * 2}\n"
            f"fpu\t\t: yes\n"
            f"fpu_exception\t: yes\n"
            f"cpuid level\t: 16\n"
            f"wp\t\t: yes\n"
            f"flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge "
            f"mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext "
            f"fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl nonstop_tsc "
            f"cpuid extd_apicid aperfmperf pni pclmulqdq monitor ssse3 fma cx16 "
            f"sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand lahf_lm cmp_legacy "
            f"svm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw ibs "
            f"skinit wdt tce topoext perfctr_core perfctr_nb bpext perfctr_llc "
            f"mwaitx cpb cat_l3 cdp_l3 hw_pstate ssbd mba ibrs ibpb stibp vmmcall "
            f"fsgsbase bmi1 avx2 smep bmi2 cqm rdt_a rdseed adx smap clflushopt "
            f"clwb sha_ni xsaveopt xsavec xgetbv1 xsaves cqm_llc cqm_occup_llc "
            f"cqm_mbm_total cqm_mbm_local clzero irperf xsaveerptr rdpru wbnoinvd "
            f"arat npt lbrv svm_lock nrip_save tsc_scale vmcb_clean flushbyasid "
            f"decodeassists pausefilter pfthreshold avic v_vmsave_vmload vgif "
            f"v_spec_ctrl umip rdpid overflow_recov succor smca sev sev_es\n"
            f"bugs\t\t: sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass "
            f"retbleed smt_rsb srso\n"
            f"bogomips\t: {bogomips:.2f}\n"
            f"TLB size\t: 3072 4K pages\n"
            f"clflush size\t: 64\n"
            f"cache_alignment\t: 64\n"
            f"address sizes\t: 48 bits physical, 48 bits virtual\n"
            f"power management:\n\n"
        )
    _write(out_dir / "proc" / "cpuinfo", "".join(cpu_lines))

    mem_total_kb  = s.mem_total_kb
    mem_bc_kb     = s.mem_bc_kb
    mem_used_kb   = s.mem_used_kb
    mem_free_kb   = s.mem_free_kb
    mem_avail_kb  = s.mem_avail_kb
    swap_total_kb = s.swap_total_kb
    # Page counts straight from the shared SimState (2048 kB per page)
    hugepage_pages      = s.hugepage_pages
    hugepage_free_pages = s.hugepage_free_pages

    meminfo = (
        f"MemTotal:       {mem_total_kb:>12} kB\n"
        f"MemFree:        {mem_free_kb:>12} kB\n"
        f"MemAvailable:   {mem_avail_kb:>12} kB\n"
        f"Buffers:        {_r(8_388_608, 10):>12} kB\n"
        f"Cached:         {_r(int(mem_bc_kb * 0.85), 3):>12} kB\n"
        f"SwapCached:                0 kB\n"
        f"Active:         {_r(int(mem_used_kb * 0.6), 5):>12} kB\n"
        f"Inactive:       {_r(int(mem_used_kb * 0.4), 5):>12} kB\n"
        f"Active(anon):   {_r(int(mem_used_kb * 0.55), 5):>12} kB\n"
        f"Inactive(anon):            0 kB\n"
        f"Active(file):   {_r(int(mem_used_kb * 0.05), 5):>12} kB\n"
        f"Inactive(file): {_r(int(mem_used_kb * 0.40), 5):>12} kB\n"
        f"Unevictable:    {_r(2_097_152, 5):>12} kB\n"
        f"Mlocked:        {_r(2_097_152, 5):>12} kB\n"
        f"SwapTotal:      {swap_total_kb:>12} kB\n"
        f"SwapFree:       {swap_total_kb:>12} kB\n"
        f"Dirty:          {_r(131_072, 20):>12} kB\n"
        f"Writeback:                 0 kB\n"
        f"AnonPages:      {_r(int(mem_used_kb * 0.55), 3):>12} kB\n"
        f"Mapped:         {_r(4_194_304, 5):>12} kB\n"
        f"Shmem:                  4096 kB\n"
        f"KReclaimable:   {_r(16_777_216, 5):>12} kB\n"
        f"Slab:           {_r(33_554_432, 5):>12} kB\n"
        f"SReclaimable:   {_r(16_777_216, 5):>12} kB\n"
        f"SUnreclaim:     {_r(16_777_216, 5):>12} kB\n"
        f"KernelStack:    {_r(262_144, 5):>12} kB\n"
        f"PageTables:     {_r(524_288, 5):>12} kB\n"
        f"NFS_Unstable:              0 kB\n"
        f"Bounce:                    0 kB\n"
        f"WritebackTmp:              0 kB\n"
        f"CommitLimit:    {int(mem_total_kb * 0.5 + swap_total_kb):>12} kB\n"
        f"Committed_AS:   {_r(int(mem_used_kb * 1.1), 3):>12} kB\n"
        f"VmallocTotal:   34359738367 kB\n"
        f"VmallocUsed:    {_r(2_097_152, 5):>12} kB\n"
        f"VmallocChunk:              0 kB\n"
        f"Percpu:         {_r(65_536, 5):>12} kB\n"
        f"HardwareCorrupted:         0 kB\n"
        f"AnonHugePages:  {_r(1_048_576, 10):>12} kB\n"
        f"ShmemHugePages:            0 kB\n"
        f"ShmemPmdMapped:            0 kB\n"
        f"FileHugePages:             0 kB\n"
        f"FilePmdMapped:             0 kB\n"
        f"HugePages_Total:        {hugepage_pages:>8}\n"
        f"HugePages_Free:         {hugepage_free_pages:>8}\n"
        f"HugePages_Rsvd:                0\n"
        f"HugePages_Surp:                0\n"
        f"Hugepagesize:           2048 kB\n"
        f"Hugetlb:        {hugepage_pages * 2048:>12} kB\n"
        f"DirectMap4k:    {_r(2_097_152, 3):>12} kB\n"
        f"DirectMap2M:    {_r(134_217_728, 2):>12} kB\n"
        f"DirectMap1G:    {_r(402_653_184, 1):>12} kB\n"
    )
    _write(out_dir / "proc" / "meminfo", meminfo)


# ---------------------------------------------------------------------------
# System-state commands  (all draw from SimState)
# ---------------------------------------------------------------------------

def gen_free(out_dir: Path, s: SimState) -> None:
    content = (
        f"               total        used        free      shared  buff/cache   available\n"
        f"Mem:    {s.mem_total_kb:>12} {s.mem_used_kb:>11} {s.mem_free_kb:>11} {4096:>11} {s.mem_bc_kb:>11} {s.mem_avail_kb:>11}\n"
        f"Swap:   {s.swap_total_kb:>12}           0 {s.swap_total_kb:>11}\n"
    )
    _write(out_dir / "usr" / "bin" / "free", content)


def gen_df(out_dir: Path) -> None:
    root_total  = 960_378_832
    root_used   = _r(int(root_total * random.uniform(0.35, 0.60)), 2)
    root_avail  = root_total - root_used
    root_pct    = math.ceil(root_used / root_total * 100)

    data_total  = 3_843_760_128
    data_used   = _r(int(data_total * random.uniform(0.28, 0.72)), 1)
    data_avail  = data_total - data_used
    data_pct    = math.ceil(data_used / data_total * 100)

    efi_total   = 1_046_528
    efi_used    = _r(13_312, 3)
    efi_avail   = efi_total - efi_used

    run_total   = 52_786_995
    run_used    = _r(135_168, 10)
    run_avail   = run_total - run_used
    shm_total   = 263_934_976
    user_total  = 52_786_992

    content = (
        f"Filesystem      1K-blocks       Used  Available Use% Mounted on\n"
        f"tmpfs           {run_total:>10} {run_used:>10} {run_avail:>10}   {math.ceil(run_used/run_total*100)}% /run\n"
        f"/dev/nvme0n1p2  {root_total:>10} {root_used:>10} {root_avail:>10}  {root_pct}% /\n"
        f"tmpfs           {shm_total:>10}          0 {shm_total:>10}   0% /dev/shm\n"
        f"tmpfs                5120          0       5120   0% /run/lock\n"
        f"/dev/nvme0n1p1   {efi_total:>9}  {efi_used:>9}  {efi_avail:>9}   2% /boot/efi\n"
        f"/dev/md0        {data_total:>10} {data_used:>10} {data_avail:>10}  {data_pct}% /data\n"
        f"tmpfs           {user_total:>10}          0 {user_total:>10}   0% /run/user/1000\n"
    )
    _write(out_dir / "usr" / "bin" / "df", content)
    # Also write the /bin/df alias so both paths work
    _write(out_dir / "bin" / "df", content)


# #2926: gen_dd() used to write a canned "0+1 records in ... 516 MB/s" block
# to bin/dd. It was never reachable -- cowrie keys `dd` AND `/bin/dd` to
# Command_dd, so getCommand() returned the builtin for either invocation
# form and the file was dead on arrival in every session cowrie has ever
# served. It is retired rather than promoted through txtcmds_priority_patch's
# allow-list, because Command_dd is strictly better than the canned text:
# it parses if=/of=/bs=/count=, resolves paths against the honeyfs, and
# captures self.input_data -- `cat payload | dd of=/tmp/x` is a real payload
# capture path that a static overlay would silently kill.
#
# Same reasoning retires gen_uname(): `uname`/`/bin/uname` are both
# Command_uname keys, and Command_uname renders the persona from
# cowrie.cfg's [shell] kernel_version/kernel_build_string/
# hardware_platform/operating_system keys (whose own comment requires them
# to match fakefs /proc/version). The overlay was the literal string
# "Linux", so promoting it would have replaced
# "Linux gpu01 5.15.0-119-generic #129-Ubuntu SMP ... x86_64 GNU/Linux"
# with one word -- a bigger persona tell than the one #2926 was filed for.


def gen_ss(out_dir: Path) -> None:
    def ep() -> int:
        return random.randint(40000, 62000)

    def rq() -> int:
        return random.choice([0, 0, 0, 0, random.randint(1, 512)])

    lines = [
        "Netid  State    Recv-Q  Send-Q   Local Address:Port       Peer Address:Port   Process",
        f"tcp    ESTAB    {rq():>6}  {rq():>6}  10.10.10.42:ssh          10.10.0.52:{ep()}    users:((\"sshd\",pid=938,fd=4))",
        f"tcp    ESTAB    {rq():>6}  {rq():>6}  10.10.10.42:8080         10.10.0.1:{ep()}     users:((\"python3\",pid=1847,fd=7))",
        f"tcp    ESTAB    {rq():>6}  {rq():>6}  10.10.10.42:8080         10.10.0.14:{ep()}    users:((\"python3\",pid=1847,fd=9))",
        f"tcp    ESTAB    {rq():>6}  {rq():>6}  10.10.10.42:5000         10.10.0.1:{ep()}     users:((\"python3\",pid=4102,fd=6))",
        f"tcp    ESTAB    {rq():>6}  {rq():>6}  10.10.10.42:{ep()}        10.10.1.10:ldap     users:((\"sssd_be\",pid=3012,fd=8))",
        f"tcp    ESTAB    {rq():>6}  {rq():>6}  10.10.10.42:{ep()}        10.10.1.10:kerberos users:((\"sssd_be\",pid=3012,fd=11))",
        f"tcp    ESTAB    {rq():>6}  {rq():>6}  10.10.10.42:{ep()}        10.10.1.10:445      users:((\"smbd\",pid=2745,fd=12))",
        f"tcp    ESTAB    {rq():>6}  {rq():>6}  10.10.10.42:{ep()}        10.10.1.20:445      users:((\"smbd\",pid=2745,fd=14))",
        f"tcp    ESTAB    {rq():>6}  {rq():>6}  10.10.10.42:{ep()}        10.10.0.5:48820     users:((\"node_exp\",pid=3201,fd=5))",
        f"tcp    ESTAB    {rq():>6}  {rq():>6}  10.10.10.42:{ep()}        10.10.0.1:33801     users:((\"java\",pid=4401,fd=18))",
        "tcp    LISTEN         0     128      0.0.0.0:22              0.0.0.0:*           users:((\"sshd\",pid=1412,fd=3))",
        "tcp    LISTEN         0     128      0.0.0.0:445             0.0.0.0:*           users:((\"smbd\",pid=2745,fd=4))",
        "tcp    LISTEN         0     128      0.0.0.0:8080            0.0.0.0:*           users:((\"python3\",pid=1847,fd=3))",
        "tcp    LISTEN         0     128      0.0.0.0:5000            0.0.0.0:*           users:((\"python3\",pid=4102,fd=3))",
        "tcp    LISTEN         0     128      0.0.0.0:9100            0.0.0.0:*           users:((\"node_exp\",pid=3201,fd=3))",
    ]
    _write(out_dir / "usr" / "bin" / "ss", "\n".join(lines) + "\n")


def gen_uptime(out_dir: Path, s: SimState) -> None:
    content = (
        f" {s.time_str} up {s.uptime_str},  1 user,  "
        f"load average: {s.load1}, {s.load5}, {s.load15}\n"
    )
    _write(out_dir / "usr" / "bin" / "uptime", content)


def gen_w(out_dir: Path, s: SimState) -> None:
    content = (
        f" {s.time_str} up {s.uptime_str},  1 user,  "
        f"load average: {s.load1}, {s.load5}, {s.load15}\n"
        f"USER     TTY      FROM             LOGIN@   IDLE JCPU   PCPU WHAT\n"
        f"root     pts/0    {s.mgmt_ip:<15}  {s.login_time_str}    0.00s  0.11s  0.02s w\n"
    )
    _write(out_dir / "usr" / "bin" / "w", content)


def gen_top(out_dir: Path, s: SimState) -> None:
    # Two python3 training processes consuming most RAM, consistent with mem_used
    proc1_mem_kb = int(s.mem_used_kb * 0.62)
    proc2_mem_kb = int(s.mem_used_kb * 0.28)
    proc1_mem_pct = round(proc1_mem_kb / s.mem_total_kb * 100, 1)
    proc2_mem_pct = round(proc2_mem_kb / s.mem_total_kb * 100, 1)
    mem_total_mib = round(s.mem_total_kb / 1024, 1)
    mem_free_mib  = round(s.mem_free_kb  / 1024, 1)
    mem_used_mib  = round(s.mem_used_kb  / 1024, 1)
    mem_bc_mib    = round(s.mem_bc_kb    / 1024, 1)
    mem_avail_mib = round(s.mem_avail_kb / 1024, 1)
    swap_total_mib = round(s.swap_total_kb / 1024, 1)
    swap_used_mib  = round(_r(492544, 5) / 1024, 1)  # small swap usage
    swap_free_mib  = round((s.swap_total_kb * 1024 - _r(492544, 5) * 1024) / 1024 / 1024, 1)

    content = (
        f"top - {s.time_str} up {s.uptime_str},  1 user,  "
        f"load average: {s.load1}, {s.load5}, {s.load15}\n"
        f"Tasks: 487 total,   2 running, 485 sleeping,   0 stopped,   0 zombie\n"
        f"%Cpu(s): {s.cpu_us:>4} us, {s.cpu_sy:>4} sy, {s.cpu_ni:>4} ni, {s.cpu_id:>5} id, "
        f"{s.cpu_wa:>4} wa, {s.cpu_hi:>4} hi, {s.cpu_si:>4} si, {s.cpu_st:>4} st\n"
        f"MiB Mem :{mem_total_mib:>10.1f} total, {mem_free_mib:>9.1f} free, "
        f"{mem_used_mib:>9.1f} used, {mem_bc_mib:>9.1f} buff/cache\n"
        f"MiB Swap:{swap_total_mib:>10.1f} total, {swap_free_mib:>9.1f} free, "
        f"{swap_used_mib:>9.1f} used. {mem_avail_mib:>9.1f} avail Mem\n"
        f"\n"
        f"  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n"
        f" 2341 root      20   0  {int(proc1_mem_kb*1.12)//1024:.1f}g  {proc1_mem_kb//1024:.1f}g "
        f"  1.2g S  {_r(974, 3) / 10:.1f}  {proc1_mem_pct}  {random.randint(40000,60000)}:{random.randint(0,59):02d}.{random.randint(0,99):02d} python3\n"
        f" 2198 root      20   0  {int(proc2_mem_kb*1.15)//1024:.1f}g  {proc2_mem_kb//1024:.1f}g "
        f"812.4m S  {_r(412, 3) / 10:.1f}  {proc2_mem_pct}  {random.randint(18000,28000)}:{random.randint(0,59):02d}.{random.randint(0,99):02d} python3\n"
        f" 1872 nobody    20   0   12.4g   4.2g  88.2m S   2.1   1.7   {random.randint(1600,2100)}:{random.randint(0,59):02d}.{random.randint(0,99):02d} prometheus\n"
        f"  941 root      20   0  721.4m  {_r(44200, 5)}k  18.1m S   0.7   0.0    {random.randint(200,280)}:{random.randint(0,59):02d}.{random.randint(0,99):02d} dockerd\n"
        f"  312 root      20   0  312.4m  12.1m   8.4m S   0.3   0.0     {random.randint(70,110)}:{random.randint(0,59):02d}.{random.randint(0,99):02d} containerd\n"
        f"  187 root      20   0   78.2m   6.1m   4.2m S   0.1   0.0     {random.randint(18,28)}:{random.randint(0,59):02d}.{random.randint(0,99):02d} systemd-journal\n"
        f"    1 root      20   0  169.4m  13.2m   8.1m S   0.0   0.0      {random.randint(3,6)}:{random.randint(0,59):02d}.{random.randint(0,99):02d} systemd\n"
        f"  421 root      20   0   48.2m   4.8m   3.1m S   0.0   0.0      {random.randint(1,4)}:{random.randint(0,59):02d}.{random.randint(0,99):02d} sshd\n"
        f"  388 root      20   0   32.1m   3.2m   2.4m S   0.0   0.0      {random.randint(0,2)}:{random.randint(0,59):02d}.{random.randint(0,99):02d} cron\n"
    )
    _write(out_dir / "usr" / "bin" / "top", content)


def gen_lscpu(out_dir: Path) -> None:
    mhz_cur = round(random.uniform(1499.8, 2249.9), 3)
    content = (
        f"Architecture:                    x86_64\n"
        f"CPU op-mode(s):                  32-bit, 64-bit\n"
        f"Byte Order:                      Little Endian\n"
        f"Address sizes:                   48 bits physical, 48 bits virtual\n"
        f"CPU(s):                          128\n"
        f"On-line CPU(s) list:             0-127\n"
        f"Thread(s) per core:              2\n"
        f"Core(s) per socket:              32\n"
        f"Socket(s):                       2\n"
        f"NUMA node(s):                    2\n"
        f"Vendor ID:                       AuthenticAMD\n"
        f"CPU family:                      23\n"
        f"Model:                           49\n"
        f"Model name:                      AMD EPYC 7742 64-Core Processor\n"
        f"Stepping:                        0\n"
        f"Frequency boost:                 enabled\n"
        f"CPU MHz:                         {mhz_cur}\n"
        f"CPU max MHz:                     2250.0000\n"
        f"CPU min MHz:                     1500.0000\n"
        f"BogoMIPS:                        {round(mhz_cur * 2, 2)}\n"
        f"Virtualization:                  AMD-V\n"
        f"L1d cache:                       2 MiB\n"
        f"L1i cache:                       2 MiB\n"
        f"L2 cache:                        32 MiB\n"
        f"L3 cache:                        512 MiB\n"
        f"NUMA node0 CPU(s):               0-63\n"
        f"NUMA node1 CPU(s):               64-127\n"
        f"Vulnerability Itlb multihit:     Not affected\n"
        f"Vulnerability L1tf:              Not affected\n"
        f"Vulnerability Mds:               Not affected\n"
        f"Vulnerability Meltdown:          Not affected\n"
        f"Vulnerability Spec store bypass: Mitigation; Speculative Store Bypass disabled via prctl and seccomp\n"
        f"Vulnerability Spectre v1:        Mitigation; usercopy/swapgs barriers and __user pointer sanitization\n"
        f"Vulnerability Spectre v2:        Mitigation; Full AMD retpoline, IBPB conditional, IBRS_FW, STIBP conditional, RSB filling\n"
        f"Vulnerability Srbds:             Not affected\n"
        f"Vulnerability Tsx async abort:   Not affected\n"
        f"Flags:                           fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl nonstop_tsc cpuid extd_apicid aperfmperf pni pclmulqdq monitor ssse3 fma cx16 sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand lahf_lm cmp_legacy svm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw ibs skinit wdt tce topoext perfctr_core perfctr_nb bpext perfctr_llc mwaitx cpb cat_l3 cdp_l3 hw_pstate sme ssbd mba sev ibrs ibpb stibp vmmcall fsgsbase bmi1 avx2 smep bmi2 cqm rdt_a rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 xsaves cqm_llc cqm_occup_llc cqm_mbm_total cqm_mbm_local clzero irperf xsaveerptr wbnoinvd arat npt lbrv svm_lock nrip_save tsc_scale vmcb_clean flushbyasid decodeassists pausefilter pfthreshold avic v_vmsave_vmload vgif umip rdpid overflow_recov succor smca sev_es\n"
    )
    _write(out_dir / "usr" / "bin" / "lscpu", content)


def gen_last(out_dir: Path, s: SimState) -> None:
    # Build a plausible login history going back ~8 weeks from the current date
    lines = []
    current = s.now
    # Most recent session still running
    lines.append(
        f"root     pts/0        {s.mgmt_ip:<15}  "
        f"{current.strftime('%a %b %d')} {s.login_time_str}   still logged in"
    )
    # Generate ~20 past sessions on weekdays
    dt = current - datetime.timedelta(hours=random.randint(8, 14))
    for _ in range(20):
        # Skip weekends occasionally
        dt -= datetime.timedelta(days=random.randint(1, 2))
        if dt.weekday() >= 5 and random.random() > 0.3:  # 70 % skip weekends
            dt -= datetime.timedelta(days=2)
        login_h = random.randint(7, 10)
        logout_h = random.randint(17, 22)
        duration_h = logout_h - login_h
        duration_m = random.randint(0, 59)
        login_dt  = dt.replace(hour=login_h,  minute=random.randint(0, 59), second=0)
        logout_dt = dt.replace(hour=logout_h, minute=random.randint(0, 59), second=0)
        pts = random.choice(["pts/0", "pts/0", "pts/0", "pts/1"])
        lines.append(
            f"root     {pts:<8}     {s.mgmt_ip:<15}  "
            f"{login_dt.strftime('%a %b %d %H:%M')} - {logout_dt.strftime('%H:%M')}  "
            f"({duration_h:02d}:{duration_m:02d})"
        )
    # Trailing wtmp line — system boot day
    boot_dt = current - datetime.timedelta(days=s.uptime_days)
    lines.append("")
    lines.append(f"wtmp begins {boot_dt.strftime('%a %b %d %H:%M:%S %Y')}")
    _write(out_dir / "usr" / "bin" / "last", "\n".join(lines) + "\n")


def gen_lastlog(out_dir: Path, s: SimState) -> None:
    ts = s.now.strftime("%a %b %d %H:%M:%S +0000 %Y")
    system_accounts = [
        "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail",
        "news", "uucp", "proxy", "www-data", "backup", "list", "irc",
        "nobody", "systemd-network", "systemd-resolve", "messagebus",
        "syslog", "_apt", "tss", "uuidd", "tcpdump", "postfix",
    ]
    lines = [f"Username         Port     From             Latest"]
    lines.append(f"root             pts/0    {s.mgmt_ip:<15}  {ts}")
    for acct in system_accounts:
        lines.append(f"{acct:<25}                   **Never logged in**")
    _write(out_dir / "usr" / "bin" / "lastlog", "\n".join(lines) + "\n")


def gen_nproc(out_dir: Path) -> None:
    # #2926: cowrie ships its own static txtcmds/data/usr/bin/nproc (a
    # hardcoded "2") with no generator overriding it, so it silently
    # disagreed with gen_lscpu's CPU(s): 128 in the same session -- the
    # cheapest two-command tell of a faked persona. Matches gen_lscpu's own
    # hardcoded 128 (no shared SimState core-count field exists to derive
    # this from instead).
    _write(out_dir / "usr" / "bin" / "nproc", "128\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <txtcmds_root>", file=sys.stderr)
        sys.exit(1)
    root = Path(sys.argv[1])
    s = SimState()
    gen_proc_files(root, s)
    gen_free(root, s)
    gen_df(root)
    gen_ss(root)
    gen_uptime(root, s)
    gen_w(root, s)
    gen_top(root, s)
    gen_lscpu(root)
    gen_nproc(root)
    gen_last(root, s)
    gen_lastlog(root, s)


if __name__ == "__main__":
    main()
