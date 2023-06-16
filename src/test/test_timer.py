import unittest
from .util import init_cpu
from ..core.riscv import TrapCause, CLINT_MTIME_LOW, CLINT_MTIMECMP_HIGH, CLINT_MTIMECMP_LOW

class TimerTest(unittest.TestCase):
    def test_read_the_timer_low(self):
        (rv, n, _) = init_cpu(f"""
            li x1, {CLINT_MTIME_LOW}
            lw x2, 0(x1)
        """)

        # In memory, this will be [fe ca de c0 ef be ad de]
        rv.state.cycle = 0xdeadbeefc0decafe

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[2], 0xc0decb00)

    def test_read_the_timer_high(self):
        (rv, n, _) = init_cpu(f"""
            li x1, {CLINT_MTIME_LOW}
            addi x1, x1, 4
            lw x2, 0(x1)
        """)

        # In memory, this will be [fe ca de c0 ef be ad de]
        rv.state.cycle = 0xdeadbeefc0decafe

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.regs[2], 0xdeadbeef)

    def test_write_the_timer_fails_low(self):
        (rv, n, _) = init_cpu(f"""
            lui x1, 0x55555
            li x2, {CLINT_MTIME_LOW}
            sw x1, 0(x2)
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertNotEqual(rv.state.cycle, 0x55555000)
        self.assertEqual(rv.state.mcause, TrapCause.IllegalInstruction)

    def test_write_the_timer_fails_high(self):
        (rv, n, _) = init_cpu(f"""
            lui x1, 0x55555
            li x2, {CLINT_MTIME_LOW}
            sw x1, 4(x2)
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertNotEqual(rv.state.cycle, 0x55555000)
        self.assertEqual(rv.state.mcause, TrapCause.IllegalInstruction)

    def test_write_timecmp_high(self):
        (rv, n, _) = init_cpu(f"""
            lui x1, 0x55555
            li x2, {CLINT_MTIMECMP_HIGH}
            sw x1, 0(x2)
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.mtimecmp, 0x5555500000000000)

    def test_write_timecmp_low(self):
        (rv, n, _) = init_cpu(f"""
            lui x1, 0x55555
            li x2, {CLINT_MTIMECMP_LOW}
            sw x1, 0(x2)
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.mtimecmp, 0x55555000)

    def test_write_timecmp_high_hw(self):
        (rv, n, _) = init_cpu(f"""
            li x1, 0xabcd
            li x2, {CLINT_MTIMECMP_HIGH}
            sh x1, 0(x2)
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.mtimecmp, 0x0000abcd00000000)

    def test_write_timecmp_high_hw2(self):
        (rv, n, _) = init_cpu(f"""
            li x1, 0xabcd
            li x2, {CLINT_MTIMECMP_HIGH}
            sh x1, 2(x2)
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.mtimecmp, 0xabcd000000000000)

    def test_write_timecmp_low_hw(self):
        (rv, n, _) = init_cpu(f"""
            li x1, 0xabcd
            li x2, {CLINT_MTIMECMP_LOW}
            sh x1, 0(x2)
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.mtimecmp, 0x000000000000abcd)

    def test_write_timecmp_low_hw2(self):
        (rv, n, _) = init_cpu(f"""
            li x1, 0xabcd
            li x2, {CLINT_MTIMECMP_LOW}
            sh x1, 2(x2)
        """)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.mtimecmp, 0x00000000abcd0000)

    def test_timer_interrupt(self):
        (rv, n, symbols) = init_cpu(f"""
                j main

            timer_interrupt_handler:
                li x2, 0xdeadbeef
                lui x3, 0x20001
                sw x2, 0(x3)
                li x2, -1
                sw x2, 0(x1)
                mret

            main:
                # Setup mtvec
                lui x1, %hi(timer_interrupt_handler)
                addi x1, x1, %lo(timer_interrupt_handler)
                csrw mtvec, x1

                # Enable the timer interrupt
                li x1, (1 << {TrapCause.MachineTimerInterrupt & 0xffff})
                csrs mie, x1

                # Setup mtimecmp
                li x1, {CLINT_MTIMECMP_LOW}
                li x2, 0x0000000d
                sw x2, 0(x1)

                # Enable interrupts
                csrsi mstatus, (1<<3)

                # 11 cycles have already past, wait another 3, and expect the timer to have elapsed
                nop
                nop
                nop

                # This code is expected to run
                li x1, 42

            last_instruction:
                # This code is not expected to run
                li x2, 0
        """)

        for _ in range(n-1):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.pc, symbols["last_instruction"])
        self.assertEqual(rv.ram_read32(0x20001000), 0xdeadbeef)
        self.assertEqual(rv.state.regs[2], 0xffffffff)

    def test_timer_wfi(self):
        (rv, n, symbols) = init_cpu(f"""
                j main

            timer_interrupt_handler:
                nop
                mret

            main:
                # Setup mtvec
                lui x1, %hi(timer_interrupt_handler)
                addi x1, x1, %lo(timer_interrupt_handler)
                csrw mtvec, x1

                # Enable the timer interrupt
                li x1, (1 << {TrapCause.MachineTimerInterrupt & 0xffff})
                csrs mie, x1

                # Setup mtimecmp
                li x1, {CLINT_MTIMECMP_LOW}
                li x2, 0x000000ff
                sw x2, 0(x1)

                # Enable interrupts
                csrsi mstatus, (1<<3)

                # 11 cycles have already past, need to wait for another 244
                wfi

            last_instruction:
                # This code is not expected to run
                li x2, 42
        """)

        for _ in range(0xff):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.pc, symbols["last_instruction"])
        self.assertEqual(rv.state.regs[2], 0xff)

        # Note: This executes the first instruction of the interrupt handler, so account for that offset
        rv.fetch_decode_execute()
        self.assertEqual(rv.state.pc, symbols["timer_interrupt_handler"] + 4)

    # TODO: Tests that have mie bits clear, but mip remain set, then mie is set later

if __name__ == "__main__":
    unittest.main()
