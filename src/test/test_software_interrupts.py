import unittest
from .util import init_cpu
from ..core.riscv import TrapCause, CLINT_MSIP, STATUS_MIE, IE_MSIE

class SoftwareInterruptsTest(unittest.TestCase):
    def test_soft_interrupt_enabled(self):
        (rv, n, symbols) = init_cpu(f"""
                j main
            interrupt_handler:
                nop
            main:
                # Setup mtvec
                lui x1, %hi(interrupt_handler)
                addi x1, x1, %lo(interrupt_handler)
                csrw mtvec, x1

                # Enable the interrupt
                csrwi mie, {1 << IE_MSIE}

                # Enable interrupts in general
                csrsi mstatus, {1 << STATUS_MIE}

                li x1, {CLINT_MSIP}
                li x2, 1            # Signal for interrupt
                sb x2, 0(x1)
                li x1, -1
        """)

        for _ in range(n-1):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.pc, symbols["interrupt_handler"] + 4)
        self.assertEqual(rv.state.mcause, TrapCause.MachineSoftwareInterrupt)

    def test_soft_interrupt_disabled(self):
        (rv, n, symbols) = init_cpu(f"""
                j main
            interrupt_handler:
                nop
            main:
                # Setup mtvec
                lui x1, %hi(interrupt_handler)
                addi x1, x1, %lo(interrupt_handler)
                csrw mtvec, x1

                # Enable interrupts in general
                csrsi mstatus, {1 << STATUS_MIE}

                li x1, {CLINT_MSIP}
                li x2, 1            # Signal for interrupt
                sb x2, 0(x1)
                li x1, -1
            program_end:
        """)

        for _ in range(n-1):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.pc, symbols["program_end"])
        self.assertEqual(rv.state.mcause, 0)
        self.assertEqual(rv.state.regs[1], 0xffffffff)

    def test_soft_mie_clear(self):
        (rv, n, symbols) = init_cpu(f"""
                j main
            interrupt_handler:
                nop
            main:
                # Setup mtvec
                lui x1, %hi(interrupt_handler)
                addi x1, x1, %lo(interrupt_handler)
                csrw mtvec, x1

                # Enable the interrupt
                csrwi mie, {1 << IE_MSIE}

                li x1, {CLINT_MSIP}
                li x2, 1            # Signal for interrupt
                sb x2, 0(x1)
                li x1, -1
            program_end:
        """)

        for _ in range(n-1):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.pc, symbols["program_end"])
        self.assertEqual(rv.state.mcause, 0)
        self.assertEqual(rv.state.regs[1], 0xffffffff)

if __name__ == "__main__":
    unittest.main()
