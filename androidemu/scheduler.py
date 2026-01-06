import time

from loguru import logger
from unicorn import (
    UC_PROT_EXEC,
    UC_PROT_READ,
    UcError,
    UC_ERR_READ_UNMAPPED,
    UC_ERR_WRITE_UNMAPPED,
    UC_ERR_FETCH_UNMAPPED,
    UC_ERR_INSN_INVALID,
)
from unicorn.arm64_const import (
    UC_ARM64_REG_PC,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_TPIDR_EL0,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X30,
)
from unicorn.arm_const import (
    UC_ARM_REG_C13_C0_3,
    UC_ARM_REG_CPSR,
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
    UC_ARM_REG_R0,
    UC_ARM_REG_SP,
)

from . import config
from .const import emu_const


class Task:
    def __init__(self):
        self.entry = 0
        self.context = None
        self.tid = 0
        self.init_stack_ptr = 0
        self.tls_ptr = 0
        self.is_init = True
        self.is_main = False
        self.is_exit = False
        self.halt_ts = -1
        self.blocking_timeout = -1
        self.signal_mask = 0
        self.priority = 0


class Scheduler:
    def __init__(self, emu):
        self.__emu = emu
        self.__mu = self.__emu.mu
        self.__pid = self.__emu.get_pcb().get_pid()
        self.__next_sub_tid = self.__pid + 1
        self.__ordered_tasks_list = []
        self.__tasks_map = {}
        self.__defer_task_map = {}
        self.__tid_2_remove = set()
        self.__cur_tid = 0

        self.__emu.memory.map(
            config.STOP_MEMORY_BASE,
            config.STOP_MEMORY_SIZE,
            UC_PROT_READ | UC_PROT_EXEC,
        )
        self.__stop_pos = config.STOP_MEMORY_BASE
        self.__futex_blocking_map = {}
        self.__blocking_set = set()

    def __get_pc(self):
        if self.__emu.get_arch() == emu_const.ARCH_ARM32:
            return self.__emu.mu.reg_read(UC_ARM_REG_PC)
        else:
            return self.__emu.mu.reg_read(UC_ARM64_REG_PC)

    def __clear_reg0(self):
        if self.__emu.get_arch() == emu_const.ARCH_ARM32:
            self.__mu.reg_write(UC_ARM_REG_R0, 0)
        else:
            self.__mu.reg_write(UC_ARM64_REG_X0, 0)

    def __set_sp(self, sp):
        if self.__emu.get_arch() == emu_const.ARCH_ARM32:
            self.__emu.mu.reg_write(UC_ARM_REG_SP, sp)
        else:
            self.__emu.mu.reg_write(UC_ARM64_REG_SP, sp)

    def __set_tls(self, tls_ptr):
        if self.__emu.get_arch() == emu_const.ARCH_ARM32:
            self.__emu.mu.reg_write(UC_ARM_REG_C13_C0_3, tls_ptr)
        else:
            self.__emu.mu.reg_write(UC_ARM64_REG_TPIDR_EL0, tls_ptr)

    def __get_interrupted_entry(self):
        pc = self.__get_pc()
        if self.__emu.get_arch() == emu_const.ARCH_ARM32:
            cpsr = self.__emu.mu.reg_read(UC_ARM_REG_CPSR)
            if cpsr & (1 << 5):  # Thumb bit
                pc = pc | 1
        return pc

    def __create_task(self, tid, stack_ptr, context, is_main, tls_ptr, signal_mask=0):
        t = Task()
        t.tid = tid
        t.init_stack_ptr = stack_ptr
        t.context = context
        t.is_main = is_main
        t.tls_ptr = tls_ptr
        t.signal_mask = signal_mask
        return t

    def __set_main_task(self):
        tid = self.__emu.get_pcb().get_pid()
        if tid in self.__tasks_map:
            # Main task already exists, just reset context if needed or ignore
            return
        t = self.__create_task(tid, 0, None, True, 0, signal_mask=0)
        self.__tasks_map[tid] = t
        self.__ordered_tasks_list.append(tid)

    def sleep(self, ms):
        tid = self.__cur_tid
        if tid in self.__tasks_map:
            self.__blocking_set.add(tid)
            self.__tasks_map[tid].blocking_timeout = ms
            self.yield_task()

    def futex_wait(self, futex_ptr, timeout=-1):
        if futex_ptr not in self.__futex_blocking_map:
            self.__futex_blocking_map[futex_ptr] = set()

        tid = self.get_current_tid()
        self.__futex_blocking_map[futex_ptr].add(tid)
        self.__blocking_set.add(tid)
        self.__tasks_map[tid].blocking_timeout = timeout
        self.yield_task()

    def futex_wake(self, futex_ptr):
        if futex_ptr in self.__futex_blocking_map:
            block_set = self.__futex_blocking_map[futex_ptr]
            if block_set:
                tid = block_set.pop()
                if tid in self.__blocking_set:
                    self.__blocking_set.remove(tid)
                logger.debug(f"futex_wake unblocked tid {tid}")
                return True
        return False

    def futex_requeue(self, src_ptr, dst_ptr):
        if src_ptr in self.__futex_blocking_map:
            block_set = self.__futex_blocking_map[src_ptr]
            if block_set:
                tid = block_set.pop()
                # Move to dst_ptr
                if dst_ptr not in self.__futex_blocking_map:
                    self.__futex_blocking_map[dst_ptr] = set()

                self.__futex_blocking_map[dst_ptr].add(tid)
                logger.debug(
                    f"futex_requeue moved tid {tid} from 0x{src_ptr:x} to 0x{dst_ptr:x}"
                )
                return True
        return False

    def add_sub_task(self, stack_ptr, tls_ptr=0):
        tid = self.__next_sub_tid
        ctx = self.__emu.mu.context_save()
        # Inherit signal mask from current task
        parent_mask = 0
        if self.__cur_tid in self.__tasks_map:
            parent_mask = self.__tasks_map[self.__cur_tid].signal_mask

        t = self.__create_task(
            tid, stack_ptr, ctx, False, tls_ptr, signal_mask=parent_mask
        )
        self.__defer_task_map[tid] = t
        self.__next_sub_tid += 1
        return tid

    def get_current_tid(self):
        return self.__cur_tid

    def yield_task(self):
        self.__emu.mu.emu_stop()

    def exit_current_task(self):
        if self.__cur_tid in self.__tasks_map:
            self.__tasks_map[self.__cur_tid].is_exit = True
            self.__tid_2_remove.add(self.__cur_tid)
            self.yield_task()

    def exec(self, main_entry, clear_task_when_return=True):
        self.__set_main_task()

        # Set return address to stop memory to catch function exit
        if self.__emu.get_arch() == emu_const.ARCH_ARM32:
            self.__emu.mu.reg_write(UC_ARM_REG_LR, self.__stop_pos)
        else:
            self.__emu.mu.reg_write(UC_ARM64_REG_X30, self.__stop_pos)

        while True:
            # Iterate over a copy of the list to allow modification during iteration
            current_tasks = list(self.__ordered_tasks_list)

            # Optimization: If no tasks, break
            if not current_tasks:
                break

            for tid in current_tasks:
                if tid not in self.__tasks_map:
                    continue  # Task might have been removed

                task = self.__tasks_map[tid]

                # --- Handle Blocking ---
                if tid in self.__blocking_set:
                    if len(self.__ordered_tasks_list) == 1:
                        # Only one task and it's blocked
                        if task.blocking_timeout < 0:
                            raise RuntimeError(
                                f"Deadlock: Task {tid} blocked indefinitely."
                            )

                        # Fast forward time
                        sleep_time = max(0, task.blocking_timeout / 1000.0)
                        logger.debug(f"Sleeping {sleep_time}s for single task {tid}")
                        time.sleep(sleep_time)
                        self.__blocking_set.remove(tid)
                        task.blocking_timeout = -1
                    else:
                        # Check timeout
                        if task.blocking_timeout > 0:
                            now = int(time.time() * 1000)
                            if (
                                task.halt_ts > 0
                                and (now - task.halt_ts) >= task.blocking_timeout
                            ):
                                logger.debug(f"Task {tid} wake up (timeout)")
                                self.__blocking_set.remove(tid)
                                task.blocking_timeout = -1
                            else:
                                continue  # Still sleeping
                        else:
                            continue  # Blocked indefinitely (futex)

                # --- Run Task ---
                self.__cur_tid = tid
                start_pos = 0

                if task.is_main:
                    if task.is_init:
                        start_pos = main_entry
                        task.is_init = False
                    else:
                        self.__emu.mu.context_restore(task.context)
                        start_pos = self.__get_interrupted_entry()
                else:
                    # Sub-thread
                    self.__emu.mu.context_restore(task.context)
                    start_pos = self.__get_interrupted_entry()
                    if task.is_init:
                        self.__set_sp(task.init_stack_ptr)
                        if task.tls_ptr:
                            self.__set_tls(task.tls_ptr)
                        self.__clear_reg0()  # Return 0 for child thread
                        task.is_init = False

                # Execute
                try:
                    # logger.trace(f"Exec tid {tid} at 0x{start_pos:X}")
                    self.__emu.mu.emu_start(start_pos, self.__stop_pos)
                except UcError as e:
                    # Basic Signal Dispatching Logic
                    sig = 0
                    if e.errno in (
                        UC_ERR_READ_UNMAPPED,
                        UC_ERR_WRITE_UNMAPPED,
                        UC_ERR_FETCH_UNMAPPED,
                    ):
                        sig = 11  # SIGSEGV
                    elif e.errno == UC_ERR_INSN_INVALID:
                        sig = 4  # SIGILL

                    if sig != 0:
                        handlers = self.__emu.get_pcb().signal_handlers
                        if sig in handlers:
                            handler_addr = handlers[sig]
                            logger.warning(
                                f"Intercepted Exception {e}, Dispatching Signal {sig} to handler 0x{handler_addr:X}"
                            )

                            # Dispatch signal via SyscallHooks helper
                            # We assume SyscallHooks is available on Emulator (added in previous step)
                            if hasattr(self.__emu, "syscall_hooks"):
                                self.__emu.syscall_hooks.setup_signal_frame(
                                    tid, sig, handler_addr
                                )
                                # After setup, we need to update context because we are currently in "exception state"
                                # But we are outside emu_start.
                                # The task.context will be updated at end of loop?
                                # No, we modify MU registers directly here.
                                # When we loop back, context_save() will capture the NEW state (PC=Handler, SP=Frame).
                                # Then next loop iteration restores this context and resumes.
                                # So we just need to NOT re-raise exception.
                                logger.info(
                                    "Signal dispatched. Resuming execution at handler."
                                )
                                # Important: Clear the exception state? Unicorn doesn't have partial state to clear.
                                # We just resume.
                            else:
                                logger.error(
                                    "SyscallHooks not found on Emulator. Cannot dispatch signal."
                                )
                                raise e
                        else:
                            logger.error(
                                f"Emulation execution error in tid {tid}: {e} (No handler for sig {sig})"
                            )
                            raise e
                    else:
                        logger.error(f"Emulation execution error in tid {tid}: {e}")
                        raise e
                except Exception as e:
                    logger.error(f"Emulation execution error in tid {tid}: {e}")
                    raise e

                task.halt_ts = int(time.time() * 1000)
                task.context = self.__emu.mu.context_save()

                # Check Exit Condition
                current_pc = self.__get_pc()
                if current_pc == self.__stop_pos or task.is_exit:
                    self.__tid_2_remove.add(tid)

            # --- Cleanup Removed Tasks ---
            for tid in self.__tid_2_remove:
                if tid in self.__tasks_map:
                    self.__tasks_map.pop(tid)
                if tid in self.__ordered_tasks_list:
                    self.__ordered_tasks_list.remove(tid)
            self.__tid_2_remove.clear()

            # --- Add New Tasks ---
            for tid, task in self.__defer_task_map.items():
                self.__tasks_map[tid] = task
                self.__ordered_tasks_list.append(tid)
            self.__defer_task_map.clear()

            # --- Main Thread Exit Check ---
            if self.__pid not in self.__tasks_map:
                logger.info(f"Main thread {self.__pid} exited. Stopping scheduler.")
                if clear_task_when_return:
                    self.__tasks_map.clear()
                return

    def get_signal_mask(self, tid):
        if tid in self.__tasks_map:
            return self.__tasks_map[tid].signal_mask
        return 0

    def set_signal_mask(self, tid, mask):
        if tid in self.__tasks_map:
            self.__tasks_map[tid].signal_mask = mask

    def get_priority(self, tid):
        if tid in self.__tasks_map:
            return self.__tasks_map[tid].priority
        return 0

    def set_priority(self, tid, priority):
        if tid in self.__tasks_map:
            self.__tasks_map[tid].priority = priority
            logger.debug(f"Set tid {tid} priority to {priority}")
