import unittest
from .util import init_cpu
from ..core.riscv import TrapCause, PrivMode

class SystemTest(unittest.TestCase):
    def test_ecall_m_mode(self):
        (rv, n, _) = init_cpu("""
            ecall
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.mcause, TrapCause.EnvironmentCallFromMMode)
        self.assertEqual(rv.state.mepc, 0x20000004)
        self.assertEqual(rv.state.mtval, 0)

    def test_ebreak(self):
        (rv, n, _) = init_cpu("""
            ebreak
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.mcause, TrapCause.Breakpoint)
        self.assertEqual(rv.state.mepc, 0x20000004)
        self.assertEqual(rv.state.mtval, 0)

    # These tests choose mstatus somewhat arbitrarily, as it's non-functional fields
    # WPRI (reserved writes preserve values, reads ignore values) - which means all fields
    # can be legally written without any bits being filtered or causing traps
    def test_csrrw(self):
        (rv, n, _) = init_cpu("""
            lui x2, 0xdeadc
            addi x2, x2, -0x111
            csrrw x2, mstatus, x2
            csrrw x2, mstatus, x2
        """)

        # Preload mstatus with a value
        rv.state.mstatus = 0xc0decafe

        # Perform the loads and the first csrrw
        for _ in range(3):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.mstatus, 0xdeadbeef)
        self.assertEqual(rv.state.regs[2], 0xc0decafe)

        rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[2], 0xdeadbeef)
        self.assertEqual(rv.state.mstatus, 0xc0decafe)

    def test_csrrs(self):
        (rv, n, _) = init_cpu("""
            lui x2, 0x01020
            addi x2, x2, 0x304
            csrrs x3, mstatus, x2
        """)

        # Preload mstatus with a value
        rv.state.mstatus = 0x06070809

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.mstatus, 0x06070809 | 0x01020304)
        self.assertEqual(rv.state.regs[3], 0x06070809)

    def test_csrrc(self):
        (rv, n, _) = init_cpu("""
            lui x2, 0x01020
            addi x2, x2, 0x304
            csrrc x3, mstatus, x2
        """)

        # Preload mstatus with a value
        rv.state.mstatus = 0x06070809

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.mstatus, 0x06050809)
        self.assertEqual(rv.state.regs[3], 0x06070809)

    def test_mret(self):
        (rv, n, _) = init_cpu("""
            # Setup the mtstatus register mpie = 1, mie = 1, mpp = supervisor
            li t0, (1 << 3) | (1 << 7) | (1 << 11)
            csrw mstatus, t0

            # Setup the mpec register
            li t0, 0x20001000
            csrw mepc, t0

            # Change context to supervisor
            mret
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.current_mode, PrivMode.Supervisor)
        self.assertEqual(rv.state.pc, 0x20001000)
        self.assertEqual(rv.state.mstatus, (1 << 3) | (PrivMode.Supervisor << 11)) # mie, mpp

    def test_sret(self):
        (rv, n, _) = init_cpu("""
            # Setup the mstatus register mpie = 1, mie = 1, mpp = supervisor
            li t0, (1 << 3) | (1 << 7) | (1 << 11)
            csrw mstatus, t0

            # Setup the mepc register
            lui t0, %hi(supervisor_entry)
            addi t0, t0, %lo(supervisor_entry)
            csrw mepc, t0

            # Change context to supervisor
            mret

            # A few nops to ensure that mret does in fact redirect the pc
            nop
            nop
            nop

            supervisor_entry:
            # Setup sstatus register spie = 1, sie = 0, spp = user
            li t0, (1 << 5)
            csrw sstatus, t0

            # Setup sepc register
            li t0, 0x20002000
            csrw sepc, t0

            # Change context to user
            sret
        """)

        # Run all the instructions, except the 3 nops
        for _ in range(n - 3):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.current_mode, PrivMode.User)
        self.assertEqual(rv.state.pc, 0x20002000)
        self.assertEqual(rv.state.sstatus, (1 << 1)) # sie, spp

    def test_uret(self):
        (rv, n, _) = init_cpu("""
            uret
        """)

        rv.state.mtvec = 0x30000000
        rv.fetch_decode_execute()

        self.assertEqual(rv.state.current_mode, PrivMode.Machine)
        self.assertEqual(rv.state.pc, 0x30000000)
        self.assertEqual(rv.state.mcause, TrapCause.IllegalInstruction)

    def test_delegated_exception(self):
        (rv, n, _) = init_cpu("""
            uret
        """)

        rv.state.medeleg = (1 << TrapCause.IllegalInstruction)
        rv.state.mtvec = 0x30000000
        rv.state.stvec = 0x40000000
        rv.state.current_mode = PrivMode.Supervisor

        rv.fetch_decode_execute()

        self.assertEqual(rv.state.current_mode, PrivMode.Supervisor)
        self.assertEqual(rv.state.pc, 0x40000000)
        self.assertEqual(rv.state.scause, TrapCause.IllegalInstruction)

if __name__ == "__main__":
    unittest.main()
