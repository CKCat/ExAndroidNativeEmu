import os
from ..const import emu_const

s_status = """
Name:   {pkg_name}
State:  R (running)
Tgid:   1434
Pid:    1434
PPid:   197
TracerPid:      0
Uid:    10054   10054   10054   10054
Gid:    10054   10054   10054   10054
FDSize: 512
Groups: 1015 1028 3003 50054 
VmPeak:  1229168 kB
VmSize:  1115232 kB
VmLck:         0 kB
VmPin:         0 kB
VmHWM:    179992 kB
VmRSS:    179836 kB
VmData:   191904 kB
VmStk:       136 kB
VmExe:         8 kB
VmLib:     48448 kB
VmPTE:       536 kB
VmSwap:        0 kB
Threads:        105
SigQ:   0/12272
SigPnd: 0000000000000000
ShdPnd: 0000000000000000
SigBlk: 0000000000001204
SigIgn: 0000000000000000
SigCgt: 00000002000094f8
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: fffffff000000000
Cpus_allowed:   f
Cpus_allowed_list:      0-3
voluntary_ctxt_switches:        5225
nonvoluntary_ctxt_switches:     11520
"""


class ProcFS:
    def __init__(self, emu, cfg, memory_map, pcb):
        self.emu = emu
        self.cfg = cfg
        self.memory_map = memory_map
        self.pcb = pcb

    def _write_file(self, path, content):
        parent = os.path.dirname(path)
        if not os.path.exists(parent):
            os.makedirs(parent)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

    def generate_proc_file(self, vfs_filename, real_path, get_uid_func):
        """
        Check if the filename is a supported virtual proc file and generate it.
        Returns True if handled, False otherwise.
        """
        pid = self.pcb.get_pid()
        # Normalized filename for pattern matching (replace pid with self)
        filename_norm = vfs_filename.replace(str(pid), "self")

        if filename_norm == "/proc/self/maps":
            parent = os.path.dirname(real_path)
            if not os.path.exists(parent):
                os.makedirs(parent)
            with open(real_path, "w", encoding="utf-8") as f:
                self.memory_map.dump_maps(f)
            return True

        elif filename_norm == "/proc/self/cmdline":
            content = self.cfg.get("pkg_name")
            self._write_file(real_path, content)
            return True

        elif filename_norm == "/proc/self/cgroup":
            uid = get_uid_func(vfs_filename)
            content = "2:cpu:/apps\n1:cpuacct:/uid/%d\n" % uid
            self._write_file(real_path, content)
            return True

        elif filename_norm == "/proc/self/status":
            name = self.cfg.get("pkg_name")
            content = s_status.format(pkg_name=name)
            self._write_file(real_path, content)
            return True

        elif filename_norm == "/proc/cpuinfo":
            is_arm64 = self.emu.get_arch() == emu_const.ARCH_ARM64
            if is_arm64:
                content = (
                    "Processor\t: AArch64 Processor rev 4 (aarch64)\n"
                    "processor\t: 0\n"
                    "BogoMIPS\t: 38.40\n"
                    "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\n"
                    "CPU implementer\t: 0x51\n"
                    "CPU architecture: 8\n"
                    "CPU variant\t: 0xa\n"
                    "CPU part\t: 0x801\n"
                    "CPU revision\t: 4\n\n"
                    "Hardware\t: Qualcomm Technologies, Inc MSM8998\n"
                )
            else:
                content = (
                    "Processor\t: ARMv7 Processor rev 4 (v7l)\n"
                    "processor\t: 0\n"
                    "BogoMIPS\t: 38.40\n"
                    "Features\t: swp half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt vfpd32 lpae evtstrm aes pmull sha1 sha2 crc32\n"
                    "CPU implementer\t: 0x51\n"
                    "CPU architecture: 7\n"
                    "CPU variant\t: 0xa\n"
                    "CPU part\t: 0x801\n"
                    "CPU revision\t: 4\n\n"
                    "Hardware\t: Qualcomm Technologies, Inc MSM8998\n"
                )
            self._write_file(real_path, content)
            return True

        elif filename_norm == "/proc/stat":
            content = (
                "cpu  41639 986 28726 3636512 858 0 200 0 0 0\n"
                "cpu0 5675 142 5906 450450 162 0 22 0 0 0\n"
                "cpu1 5828 116 3578 454746 95 0 27 0 0 0\n"
                "intro 12345678\n"
                "ctxt 12345678\n"
                "btime 1600000000\n"
                "processes 12345\n"
                "procs_running 2\n"
                "procs_blocked 0\n"
                "softirq 123456 0 1 2 3 4\n"
            )
            self._write_file(real_path, content)
            return True

        elif filename_norm == "/proc/self/stat":
            pid = self.pcb.get_pid()
            pkg_name = self.cfg.get("pkg_name", "app_process")
            content = f"{pid} ({pkg_name}) S 100 100 0 0 -1 4202496 0 0 0 0 0 0 0 0 20 0 1 0 123456 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
            self._write_file(real_path, content)
            return True

        return False
