import unittest
from .util import init_cpu
from ..core.riscv import RVTrap, TrapCause

class LoadTest(unittest.TestCase):
    def test_lui(self):
        (rv, n, _) = init_cpu("""
            lui x1, 0x12345
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[1], 0x12345000)

    def test_auipc(self):
        (rv, n, _) = init_cpu("""
            auipc x1, 0x12345
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[1], 0x32345000)

    def test_lb_positive(self):
        (rv, n, _) = init_cpu("""
            li x1, 0x20000000
            lb x2, 0xe(x1)
            nop
            .byte 0x40, 0x41, 0x42, 0x43
        """)

        for _ in range(2):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[2], 0x42)

    def test_lb_negative(self):
        (rv, n, _) = init_cpu("""
            .byte 0x40, 0x41, 0x42, 0x43
            lui x1, 0x20000
            addi x1, x1, 8
            lb x2, -6(x1)
            nop
        """)

        rv.state.pc = 0x20000004

        for _ in range(3):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[2], 0x42)

    def test_lb_signed(self):
        (rv, n, _) = init_cpu("""
            li x1, 0x20000000
            lb x2, 0xe(x1)
            nop
            .byte 0x80, 0x81, 0x82, 0x83
        """)

        for _ in range(2):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[2], 0xffffff82)

    def test_lbu(self):
        (rv, n, _) = init_cpu("""
            li x1, 0x20000000
            lbu x2, 0xe(x1)
            nop
            .byte 0x80, 0x81, 0x82, 0x83
        """)

        for _ in range(2):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[2], 0x82)

    def test_lh_signed(self):
        (rv, n, _) = init_cpu("""
            li x1, 0x20000000
            lh x2, 0x10(x1)
            nop
            .half 0x8000, 0x8100, 0x8200, 0x8300
        """)

        for _ in range(2):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[2], 0xffff8200)

    def test_lhu(self):
        (rv, n, _) = init_cpu("""
            li x1, 0x20000000
            lhu x2, 0x10(x1)
            nop
            .half 0x8000, 0x8100, 0x8200, 0x8300
        """)

        for _ in range(2):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[2], 0x8200)

    def test_lh_unaligned(self):
        (rv, n, _) = init_cpu("""
            li x1, 0x20000000
            lh x2, 0x11(x1)
            nop
            .half 0xc0de, 0xcafe, 0xdead, 0xbeef
        """)

        for _ in range(2):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.mcause, TrapCause.LoadAddressMisaligned)
        self.assertEqual(rv.state.mepc, 0x20000008)
        self.assertEqual(rv.state.mtval, 0x20000011)

    def test_lw(self):
        (rv, n, _) = init_cpu("""
            li x1, 0x20000000
            lw x2, 0x10(x1)
            nop
            .word 0xc0decafe, 0xdeadbeef
        """)

        for _ in range(2):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[2], 0xdeadbeef)

    def test_lw_unaligned(self):
        (rv, n, _) = init_cpu("""
            li x1, 0x20000000
            lw x2, 0x12(x1)
            nop
            .word 0xc0decafe, 0xdeadbeef
        """)

        for _ in range(2):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.mcause, TrapCause.LoadAddressMisaligned)
        self.assertEqual(rv.state.mepc, 0x20000008)
        self.assertEqual(rv.state.mtval, 0x20000012)

if __name__ == "__main__":
    unittest.main()
