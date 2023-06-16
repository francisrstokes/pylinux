import unittest
from .util import init_cpu

class BranchTest(unittest.TestCase):
    def test_jal_j_positive(self):
        (rv, n, _) = init_cpu("""
            j somewhere
            nop
            nop
            somewhere:
        """)

        # Only run the jump instruction
        rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[0], 0)
        self.assertEqual(rv.state.pc, 0x2000000c)

    def test_jal_j_negative(self):
        (rv, n, _) = init_cpu("""
            somewhere:
            nop
            nop
            nop
            j somewhere
        """)

        # Set the PC to the jump instruction
        rv.state.pc = 0x2000000c

        # Only run the jump instruction
        rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[0], 0)
        self.assertEqual(rv.state.pc, 0x20000000)

    def test_jal_positive(self):
        (rv, n, _) = init_cpu("""
            jal ra, somewhere
            nop
            nop
            somewhere:
        """)

        # Only run the jump instruction
        rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[1], 0x20000004)
        self.assertEqual(rv.state.pc, 0x2000000c)

    def test_jal_negative(self):
        (rv, n, _) = init_cpu("""
            somewhere:
            nop
            nop
            nop
            jal ra, somewhere
        """)

        # Set the PC to the jump instruction
        rv.state.pc = 0x2000000c

        # Only run the jump instruction
        rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[1], 0x20000010)
        self.assertEqual(rv.state.pc, 0x20000000)

    def test_jalr_positive(self):
        (rv, n, _) = init_cpu("""
            li x2, 0x20001000
            jalr ra, x2, 0x100
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[1], 0x20000008)
        self.assertEqual(rv.state.regs[2], 0x20001000)
        self.assertEqual(rv.state.pc, 0x20001100)

    def test_jalr_negative(self):
        (rv, n, _) = init_cpu("""
            li x2, 0x20000000
            jalr ra, x2, -4
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[1], 0x20000008)
        self.assertEqual(rv.state.regs[2], 0x20000000)
        self.assertEqual(rv.state.pc, 0x1ffffffc)

    def test_beq_match(self):
        (rv, n, _) = init_cpu("""
            li x2, 1
            li x3, 1
            beq x2, x3, something
            nop
            nop
            something:
        """)

        # Execute everything up to and including the branch
        for _ in range(3):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.pc, 0x20000014)

    def test_beq_no_match(self):
        (rv, n, _) = init_cpu("""
            li x2, 1
            li x3, 2
            beq x2, x3, something
            nop
            nop
            something:
        """)

        # Execute everything up to and including the branch
        for _ in range(3):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.pc, 0x2000000c)

    def test_beq_match_negative(self):
        (rv, n, _) = init_cpu("""
            something:
            nop
            nop
            nop
            li x2, 1
            li x3, 1
            beq x2, x3, something
        """)

        # Start from the immediate loads
        rv.state.pc = 0x2000000c

        # Execute everything up to and including the branch
        for _ in range(3):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.pc, 0x20000000)

    def test_bne_match(self):
        (rv, n, _) = init_cpu("""
            li x2, 2
            li x3, 1
            bne x2, x3, something
            nop
            nop
            something:
        """)

        # Execute everything up to and including the branch
        for _ in range(3):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.pc, 0x20000014)

    def test_bne_no_match(self):
        (rv, n, _) = init_cpu("""
            li x2, 1
            li x3, 1
            bne x2, x3, something
            nop
            nop
            something:
        """)

        # Execute everything up to and including the branch
        for _ in range(3):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.pc, 0x2000000c)

    def test_bge_gt(self):
        (rv, n, _) = init_cpu("""
            li x2, 2
            li x3, -1
            bge x2, x3, something
            nop
            nop
            something:
        """)

        # Execute everything up to and including the branch
        for _ in range(3):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.pc, 0x20000014)

    def test_bge_eq(self):
        (rv, n, _) = init_cpu("""
            li x2, 1
            li x3, 1
            bge x2, x3, something
            nop
            nop
            something:
        """)

        # Execute everything up to and including the branch
        for _ in range(3):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.pc, 0x20000014)

    def test_bge_no_match(self):
        (rv, n, _) = init_cpu("""
            li x2, 1
            li x3, 2
            bge x2, x3, something
            nop
            nop
            something:
        """)

        # Execute everything up to and including the branch
        for _ in range(3):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.pc, 0x2000000c)

    def test_blt_match(self):
        (rv, n, _) = init_cpu("""
            li x2, -1
            li x3, 0
            blt x2, x3, something
            nop
            nop
            something:
        """)

        # Execute everything up to and including the branch
        for _ in range(3):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.pc, 0x20000014)

    def test_blt_gt(self):
        (rv, n, _) = init_cpu("""
            li x2, 2
            li x3, 1
            blt x2, x3, something
            nop
            nop
            something:
        """)

        # Execute everything up to and including the branch
        for _ in range(3):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.pc, 0x2000000c)

    def test_blt_eq(self):
        (rv, n, _) = init_cpu("""
            li x2, 1
            li x3, 1
            blt x2, x3, something
            nop
            nop
            something:
        """)

        # Execute everything up to and including the branch
        for _ in range(3):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.pc, 0x2000000c)

    def test_bgtu_match(self):
        (rv, n, _) = init_cpu("""
            li x2, 0xffffffff
            li x3, 0
            bgtu x2, x3, something
            nop
            nop
            something:
        """)

        # Execute everything up to and including the branch
        for _ in range(3):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.pc, 0x20000014)

    def test_bgtu_eq(self):
        (rv, n, _) = init_cpu("""
            li x2, 1
            li x3, 1
            bgtu x2, x3, something
            nop
            nop
            something:
        """)

        # Execute everything up to and including the branch
        for _ in range(3):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.pc, 0x2000000c)

    def test_bgtu_no_match(self):
        (rv, n, _) = init_cpu("""
            li x2, 0
            li x3, 1
            bgtu x2, x3, something
            nop
            nop
            something:
        """)

        # Execute everything up to and including the branch
        for _ in range(3):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.pc, 0x2000000c)

if __name__ == "__main__":
    unittest.main()
