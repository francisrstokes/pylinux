import unittest
import struct
from .util import init_cpu
from ..core.riscv import RVTrap, TrapCause

class StoreTest(unittest.TestCase):
    def test_sb_positive(self):
        (rv, n, _) = init_cpu("""
            li x1, 0x20001000
            li x2, 0x42
            sb x2, 0x111(x1)
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.mem[0x1111], 0x42)

    def test_sb_negative(self):
        (rv, n, _) = init_cpu("""
            li x1, 0x20001000
            li x2, 0x42
            sb x2, -1(x1)
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.mem[0xfff], 0x42)

    def test_sh(self):
        (rv, n, _) = init_cpu("""
            li x1, 0x20001000
            li x2, 0xc0de
            sh x2, 0x112(x1)
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        (mem_value,) = struct.unpack_from("<H", rv.mem, 0x1112)
        self.assertEqual(mem_value, 0xc0de)

    def test_sh_unaligned(self):
        (rv, n, _) = init_cpu("""
            li x1, 0x20001000
            lui x2, 0xc
            addi x2, x2, 0x0de
            sh x2, 0x111(x1)
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.mcause, TrapCause.Store_AMOAddressMisaligned)
        self.assertEqual(rv.state.mepc, 0x20000010)
        self.assertEqual(rv.state.mtval, 0x20001111)

    def test_sw(self):
        (rv, n, _) = init_cpu("""
            li x1, 0x20001000
            li x2, 0xdeadbeef
            sw x2, 0x110(x1)
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        (mem_value,) = struct.unpack_from("<I", rv.mem, 0x1110)
        self.assertEqual(mem_value, 0xdeadbeef)

    def test_sw_unaligned(self):
        (rv, n, _) = init_cpu("""
            li x1, 0x20001000
            lui x2, 0xdeadc
            addi x2, x2, -0x111
            sw x2, 0x113(x1)
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.mcause, TrapCause.Store_AMOAddressMisaligned)
        self.assertEqual(rv.state.mepc, 0x20000010)
        self.assertEqual(rv.state.mtval, 0x20001113)


if __name__ == "__main__":
    unittest.main()
