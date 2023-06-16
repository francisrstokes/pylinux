import unittest
from .util import init_cpu

class ALUTest(unittest.TestCase):
    def test_add_zeros(self):
        (rv, n, _) = init_cpu("""
            add x1, x0, x0
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[1], 0)

    def test_add_values(self):
        (rv, n, _) = init_cpu("""
            li x1, 20
            li x2, 22
            add x3, x1, x2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 42)

    def test_add_overflow(self):
        (rv, n, _) = init_cpu("""
            li x1, 0xffffffff
            li x2, 1
            add x3, x1, x2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[1], 0xffffffff)
        self.assertEqual(rv.state.regs[2], 1)
        self.assertEqual(rv.state.regs[3], 0)

    def test_sub_values(self):
        (rv, n, _) = init_cpu("""
            li x1, 5
            li x2, 1
            sub x3, x1, x2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 4)

    def test_sub_underflow(self):
        (rv, n, _) = init_cpu("""
            li x1, 1
            li x2, 5
            sub x3, x1, x2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 0xfffffffc)

    def test_sl_valid(self):
        (rv, n, _) = init_cpu("""
            li x1, 1
            li x2, 5
            sll x3, x1, x2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 1 << 5)

    def test_sl_gt_31(self):
        (rv, n, _) = init_cpu("""
            li x1, 1
            li x2, 32
            sll x3, x1, x2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 1)

    def test_slt_positive(self):
        (rv, n, _) = init_cpu("""
            li x1, 1
            li x2, 2
            slt x3, x1, x2
            slt x4, x2, x1
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 1)
        self.assertEqual(rv.state.regs[4], 0)

    def test_slt_negative(self):
        (rv, n, _) = init_cpu("""
            li x1, -1
            li x2, -2
            slt x3, x1, x2
            slt x4, x2, x1
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 0)
        self.assertEqual(rv.state.regs[4], 1)

    def test_sltu_positive(self):
        (rv, n, _) = init_cpu("""
            li x1, 1
            li x2, 2
            sltu x3, x1, x2
            sltu x4, x2, x1
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 1)
        self.assertEqual(rv.state.regs[4], 0)

    def test_sltu_negative(self):
        (rv, n, _) = init_cpu("""
            li x1, -1
            li x2, -2
            sltu x3, x1, x2
            sltu x4, x2, x1
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 0)
        self.assertEqual(rv.state.regs[4], 1)

    def test_xor(self):
        (rv, n, _) = init_cpu("""
            li x1, 0x1234
            li x2, 0xabcd
            xor x3, x1, x2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 0x1234 ^ 0xabcd)

    def test_srl(self):
        (rv, n, _) = init_cpu("""
            li x1, 0x80000000
            li x2, 16
            srl x3, x1, x2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 0x8000)

    def test_srl_gt_31(self):
        (rv, n, _) = init_cpu("""
            li x1, 0x80000000
            li x2, 32
            srl x3, x1, x2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 0x80000000)

    def test_sra(self):
        (rv, n, _) = init_cpu("""
            li x1, 0x80000000
            li x2, 16
            sra x3, x1, x2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 0xffff8000)

    def test_sra_gt_31(self):
        (rv, n, _) = init_cpu("""
            li x1, 0x80000000
            li x2, 32
            sra x3, x1, x2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 0x80000000)

    def test_or(self):
        (rv, n, _) = init_cpu("""
            li x1, 0x80000000
            li x2, 0x01020304
            or x3, x1, x2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 0x81020304)

    def test_and(self):
        (rv, n, _) = init_cpu("""
            li x1, 0xffff0000
            li x2, 0x12345678
            and x3, x1, x2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 0x12340000)

    def test_mul(self):
        (rv, n, _) = init_cpu("""
            li x1, 5
            li x2, 10
            mul x3, x1, x2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 50)

    def test_mul_negative(self):
        (rv, n, _) = init_cpu("""
            li x1, -1
            li x2, 2
            mul x3, x1, x2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 0xfffffffe)

    def test_mul_overflow(self):
        (rv, n, _) = init_cpu("""
            li x1, 0xffffffff
            li x2, 2
            mul x3, x1, x2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 0xfffffffe)

    def test_mulh(self):
        (rv, n, _) = init_cpu("""
            li x1, 0x80000000
            li x2, 0x80000000
            mulh x3, x1, x2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 0x40000000)

    def test_mulhsu(self):
        (rv, n, _) = init_cpu("""
            li x1, 0x80000000
            li x2, 0x80000000
            mulhsu x3, x1, x2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 0xc0000000)

    def test_div(self):
        (rv, n, _) = init_cpu("""
            li x1, 100
            li x2, 5
            div x3, x1, x2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 20)

    def test_div0(self):
        (rv, n, _) = init_cpu("""
            li x1, 100
            li x2, 0
            div x3, x1, x2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 0xffffffff)

    def test_div_negative(self):
        (rv, n, _) = init_cpu("""
            li x1, -100
            li x2, 5
            div x3, x1, x2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 0xffffffec)

    def test_divu(self):
        (rv, n, _) = init_cpu("""
            li x1, 100
            li x2, 5
            divu x3, x1, x2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 20)

    def test_divu_twos_negative(self):
        (rv, n, _) = init_cpu("""
            li x1, 0xffffff9c
            li x2, 5
            divu x3, x1, x2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 0x3333331f)

    def test_divu0(self):
        (rv, n, _) = init_cpu("""
            li x1, 1
            li x2, 0
            divu x3, x1, x2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 0xffffffff)

    def test_rem(self):
        (rv, n, _) = init_cpu("""
            li x1, 10
            li x2, 4
            rem x3, x1, x2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 2)

    def test_rem_negative(self):
        (rv, n, _) = init_cpu("""
            li x1, -10
            li x2, 4
            rem x3, x1, x2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 2)

    def test_rem0(self):
        (rv, n, _) = init_cpu("""
            li x1, -10
            li x2, 0
            rem x3, x1, x2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 0xfffffff6)

    def test_remu(self):
        (rv, n, _) = init_cpu("""
            li x1, 10
            li x2, 4
            remu x3, x1, x2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 2)

    def test_remu_twos_negative(self):
        (rv, n, _) = init_cpu("""
            li x1, 0x80000001
            li x2, 4
            remu x3, x1, x2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 1)

    def test_remu0(self):
        (rv, n, _) = init_cpu("""
            li x1, 0x80000001
            li x2, 0
            remu x3, x1, x2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 0x80000001)

    def test_addi(self):
        (rv, n, _) = init_cpu("""
            li x1, 20
            addi x3, x1, 22
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 42)

    def test_slti_positive(self):
        (rv, n, _) = init_cpu("""
            li x1, 1
            slti x3, x1, 2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 1)

    def test_slti_negative(self):
        (rv, n, _) = init_cpu("""
            li x1, -1
            slti x3, x1, -2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 0)

    def test_sltiu_positive(self):
        (rv, n, _) = init_cpu("""
            li x1, 1
            sltiu x3, x1, 2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 1)

    def test_sltiu_negative(self):
        (rv, n, _) = init_cpu("""
            li x1, -1
            sltiu x3, x1, -2
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 0)

    def test_xori(self):
        (rv, n, _) = init_cpu("""
            li x1, 0x1234
            xori x3, x1, -2048
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 0x1234 ^ 0xfffff800)

    def test_or(self):
        (rv, n, _) = init_cpu("""
            li x1, 0x80001234
            ori x3, x1, -2048
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 0x80001234 | 0xfffff800)

    def test_andi(self):
        (rv, n, _) = init_cpu("""
            li x1, 0x12488421
            andi x3, x1, -2048
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 0x12488421 & 0xfffff800)

    def test_sli_valid(self):
        (rv, n, _) = init_cpu("""
            li x1, 1
            slli x3, x1, 5
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 1 << 5)

    def test_srli(self):
        (rv, n, _) = init_cpu("""
            li x1, 0x80000000
            srli x3, x1, 16
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 0x8000)

    def test_srai(self):
        (rv, n, _) = init_cpu("""
            li x1, 0x80000000
            srai x3, x1, 16
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[3], 0xffff8000)

if __name__ == "__main__":
    unittest.main()
