import unittest
import struct
from .util import init_cpu
from ..core.riscv import TrapCause, PrivMode, RAM_START

def create_pte(v=0, r=0, x=0, w=0, u=0, g=0, a=0, d=0, ppn0=0, ppn1=0):
    return (ppn1 << 20) | (ppn0 << 10) | (d << 7) | (a << 6) | (g << 5) | (u << 4) | (x << 3) | (w << 2) | (r << 1) | v

class MMUTest(unittest.TestCase):
    def test_address_in_range(self):
        (rv, n, _) = init_cpu("""
            nop
        """)

        # Addresses are always translated in user mode
        rv.state.current_mode = PrivMode.User

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.current_mode, PrivMode.Machine)
        self.assertEqual(rv.state.mepc, 0x20000000)
        self.assertEqual(rv.state.mcause, TrapCause.InstructionPageFault)

    def test_valid_page_table_lookup_1_level(self):
        # Insert ~8K bytes of zeros so that the instruction to be executed
        # ends up at the desired physical address after translation
        # For a level 1 lookup, part of the virtual address is used directly in the computed
        # physical address - so place the test instruction well outside of the regular 4KiB
        # page size to ensure that works properly
        (rv, n, _) = init_cpu(f"""
            .byte {", ".join(["0"] * 0x2004)}
            li x1, 42
        """)

        page_table_address = 0x20001000
        rv.state.current_mode = PrivMode.User
        rv.state.satp = (1 << 31) | (0 << 22) | (page_table_address >> 12)
        rv.state.pc = 0x55002004 # VPN[0] = 0x002, VPN[1] = 0x154, offset = 0x004

        vpn1 = 0x154
        pte = create_pte(v=1, r=1, x=1, u=1, g=1, a=1, ppn1=0x200) # corresponds to the 0x20000000 superpage
        rv.ram_write32(page_table_address + (vpn1 * 4), pte)

        rv.fetch_decode_execute()

        self.assertEqual(rv.state.current_mode, PrivMode.User)
        self.assertEqual(rv.state.pc, 0x55002008)
        self.assertEqual(rv.state.regs[1], 42)

    def test_valid_page_table_lookup_2_level(self):
        # Place the target instruction just over 1.5 physical pages into RAM
        (rv, n, _) = init_cpu(f"""
            .byte {", ".join(["0"] * 0x184c)}
            li x1, 42
        """)

        page_table_level1_address = 0x20004000
        page_table_level2_address = 0x20002000

        rv.state.current_mode = PrivMode.User
        rv.state.satp = (1 << 31) | (0 << 22) | (page_table_level1_address >> 12)
        rv.state.pc = 0x5500284c # VPN[0] = 0x002, VPN[1] = 0x154, offset = 0x84c

        vpn1 = 0x154
        vpn0 = 0x002

        pte_parent = create_pte(v=1, a=1, ppn1=0x080, ppn0=0x002) # Next page table at 0x20002000
        pte_leaf = create_pte(v=1, r=1, x=1, u=1, a=1, ppn1=0x200, ppn0=0x001)

        rv.ram_write32(page_table_level1_address + (vpn1 * 4), pte_parent)
        rv.ram_write32(page_table_level2_address + (vpn0 * 4), pte_leaf)

        rv.fetch_decode_execute()

        self.assertEqual(rv.state.current_mode, PrivMode.User)
        self.assertEqual(rv.state.pc, 0x55002850)
        self.assertEqual(rv.state.regs[1], 42)

    def test_valid_page_no_write(self):
        offset = 0x184c
        # Place the target instruction just over 1.5 physical pages into RAM
        (rv, n, _) = init_cpu(f"""
            .byte {", ".join(["0"] * offset)}
            li x2, 0x55002800
            sw x1, 0(x2)
        """)

        page_table_level1_address = 0x20004000
        page_table_level2_address = 0x20002000

        rv.state.current_mode = PrivMode.User
        rv.state.satp = (1 << 31) | (0 << 22) | (page_table_level1_address >> 12)
        rv.state.pc = 0x5500284c # VPN[0] = 0x002, VPN[1] = 0x154, offset = 0x84c

        vpn1 = 0x154
        vpn0 = 0x002

        pte_parent = create_pte(v=1, a=1, ppn1=0x080, ppn0=0x002) # Next page table at 0x20002000
        pte_leaf = create_pte(v=1, r=1, x=1, u=1, a=1, ppn1=0x200, ppn0=0x001)

        rv.ram_write32(page_table_level1_address + (vpn1 * 4), pte_parent)
        rv.ram_write32(page_table_level2_address + (vpn0 * 4), pte_leaf)

        for _ in range(n-(offset // 4)):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.current_mode, PrivMode.Machine)
        self.assertEqual(rv.state.mcause, TrapCause.Store_AMOPageFault)

    def test_valid_page_no_read(self):
        offset = 0x184c
        # Place the target instruction just over 1.5 physical pages into RAM
        (rv, n, _) = init_cpu(f"""
            .byte {", ".join(["0"] * offset)}
            li x2, 0x55002800
            lw x1, 0(x2)
        """)

        page_table_level1_address = 0x20004000
        page_table_level2_address = 0x20002000

        rv.state.current_mode = PrivMode.User
        rv.state.satp = (1 << 31) | (0 << 22) | (page_table_level1_address >> 12)
        rv.state.pc = 0x5500284c # VPN[0] = 0x002, VPN[1] = 0x154, offset = 0x84c

        vpn1 = 0x154
        vpn0 = 0x002

        pte_parent = create_pte(v=1, a=1, ppn1=0x080, ppn0=0x002) # Next page table at 0x20002000
        pte_leaf = create_pte(v=1, x=1, u=1, a=1, ppn1=0x200, ppn0=0x001)

        rv.ram_write32(page_table_level1_address + (vpn1 * 4), pte_parent)
        rv.ram_write32(page_table_level2_address + (vpn0 * 4), pte_leaf)

        for _ in range(n-(offset // 4)):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.current_mode, PrivMode.Machine)
        self.assertEqual(rv.state.mcause, TrapCause.LoadPageFault)

    def test_valid_page_no_execute(self):
        offset = 0x184c
        # Place the target instruction just over 1.5 physical pages into RAM
        (rv, n, _) = init_cpu(f"""
            .byte {", ".join(["0"] * offset)}
            nop
        """)

        page_table_level1_address = 0x20004000
        page_table_level2_address = 0x20002000

        rv.state.current_mode = PrivMode.User
        rv.state.satp = (1 << 31) | (0 << 22) | (page_table_level1_address >> 12)
        rv.state.pc = 0x5500284c # VPN[0] = 0x002, VPN[1] = 0x154, offset = 0x84c

        vpn1 = 0x154
        vpn0 = 0x002

        pte_parent = create_pte(v=1, a=1, ppn1=0x080, ppn0=0x002) # Next page table at 0x20002000
        pte_leaf = create_pte(v=1, r=1, w=1, u=1, a=1, ppn1=0x200, ppn0=0x001)

        rv.ram_write32(page_table_level1_address + (vpn1 * 4), pte_parent)
        rv.ram_write32(page_table_level2_address + (vpn0 * 4), pte_leaf)

        for _ in range(n-(offset // 4)):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.current_mode, PrivMode.Machine)
        self.assertEqual(rv.state.mcause, TrapCause.InstructionPageFault)

    def test_valid_page_supervisor_cannot_execute_user_page(self):
        offset = 0x184c
        # Place the target instruction just over 1.5 physical pages into RAM
        (rv, n, _) = init_cpu(f"""
            .byte {", ".join(["0"] * offset)}
            nop
        """)

        page_table_level1_address = 0x20004000
        page_table_level2_address = 0x20002000

        rv.state.current_mode = PrivMode.Supervisor
        rv.state.satp = (1 << 31) | (0 << 22) | (page_table_level1_address >> 12)
        rv.state.pc = 0x5500284c # VPN[0] = 0x002, VPN[1] = 0x154, offset = 0x84c

        vpn1 = 0x154
        vpn0 = 0x002

        pte_parent = create_pte(v=1, a=1, ppn1=0x080, ppn0=0x002) # Next page table at 0x20002000
        pte_leaf = create_pte(v=1, r=1, w=1, u=1, a=1, ppn1=0x200, ppn0=0x001)

        rv.ram_write32(page_table_level1_address + (vpn1 * 4), pte_parent)
        rv.ram_write32(page_table_level2_address + (vpn0 * 4), pte_leaf)

        for _ in range(n-(offset // 4)):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.current_mode, PrivMode.Machine)
        self.assertEqual(rv.state.mcause, TrapCause.InstructionPageFault)

    def test_supervisor_sum_disabled_read_user_page(self):
        (rv, n, _) = init_cpu(f"""
            li x1, 0x54c01008
            lw x2, 0(x1)
        """)

        # Create a pte for a supervisor page and a user page. Assert that the user page cannot
        # *read* from the supervisor code when the sum bit is clear.

        page_table_address = 0x20001000
        rv.state.satp = (1 << 31) | (0 << 22) | (page_table_address >> 12)
        rv.state.sstatus = 0 # All bits clear, including the SUM bit
        rv.state.current_mode = PrivMode.Supervisor
        rv.state.pc = 0x55000000 # VPN[0] = 0x000, VPN[1] = 0x154, offset = 0x000

        vpn1 = 0x154
        pte = create_pte(v=1, r=1, x=1, g=1, a=1, ppn1=0x200) # corresponds to the 0x20000000 superpage
        rv.ram_write32(page_table_address + (vpn1 * 4), pte)

        # User target address: 0x20101008
        vpn1 = 0x153
        pte = create_pte(v=1, r=1, x=1, u=1, g=1, a=1, ppn1=0x201) # corresponds to the 0x20100000 superpage
        rv.ram_write32(page_table_address + (vpn1 * 4), pte)

        rv.ram_write32(0x20101008, 0xdeadbeef)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.current_mode, PrivMode.Machine)
        self.assertEqual(rv.state.mcause, TrapCause.LoadPageFault)
        self.assertNotEqual(rv.state.regs[2], 0xdeadbeef)

    def test_supervisor_sum_enabled_read_user_page(self):
        (rv, n, _) = init_cpu(f"""
            li x1, 0x54c01008
            lw x2, 0(x1)
        """)

        # Create a pte for a supervisor page and a user page. Assert that the user page can
        # *read* from the supervisor code when the sum bit is set.

        page_table_address = 0x20001000
        rv.state.satp = (1 << 31) | (0 << 22) | (page_table_address >> 12)
        rv.state.sstatus = (1 << 18) # SUM bit sete
        rv.state.current_mode = PrivMode.Supervisor
        rv.state.pc = 0x55000000 # VPN[0] = 0x000, VPN[1] = 0x154, offset = 0x000

        vpn1 = 0x154
        pte = create_pte(v=1, r=1, x=1, g=1, a=1, ppn1=0x200) # corresponds to the 0x20000000 superpage
        rv.ram_write32(page_table_address + (vpn1 * 4), pte)

        # User target address: 0x20101008
        vpn1 = 0x153
        pte = create_pte(v=1, r=1, x=1, u=1, g=1, a=1, ppn1=0x201) # corresponds to the 0x20100000 superpage
        rv.ram_write32(page_table_address + (vpn1 * 4), pte)

        rv.ram_write32(0x20101008, 0xdeadbeef)

        for _ in range(n):
            rv.fetch_decode_execute()

        self.assertEqual(rv.state.current_mode, PrivMode.Supervisor)
        self.assertEqual(rv.state.regs[2], 0xdeadbeef)

    def test_supervisor_sum_disabled_write_user_page(self):
        (rv, n, _) = init_cpu(f"""
            li x1, 0x54c01008
            li x2, 0xdeadbeef
            sw x2, 0(x1)
        """)

        # Create a pte for a supervisor page and a user page. Assert that the user page cannot
        # *write* from the supervisor code when the sum bit is clear.

        page_table_address = 0x20001000
        rv.state.satp = (1 << 31) | (0 << 22) | (page_table_address >> 12)
        rv.state.sstatus = 0 # All bits clear, including the SUM bit
        rv.state.current_mode = PrivMode.Supervisor
        rv.state.pc = 0x55000000 # VPN[0] = 0x000, VPN[1] = 0x154, offset = 0x000

        vpn1 = 0x154
        pte = create_pte(v=1, r=1, x=1, g=1, a=1, ppn1=0x200) # corresponds to the 0x20000000 superpage
        rv.ram_write32(page_table_address + (vpn1 * 4), pte)

        # User target address: 0x20101008
        vpn1 = 0x153
        pte = create_pte(v=1, r=1, w=1, u=1, g=1, a=1, ppn1=0x201) # corresponds to the 0x20100000 superpage
        rv.ram_write32(page_table_address + (vpn1 * 4), pte)

        for _ in range(n):
            rv.fetch_decode_execute()

        mem_value = struct.unpack_from("<I", rv.mem, 0x101008)[0]

        self.assertEqual(rv.state.current_mode, PrivMode.Machine)
        self.assertEqual(rv.state.mcause, TrapCause.Store_AMOPageFault)
        self.assertNotEqual(mem_value, 0xdeadbeef)

    def test_supervisor_sum_enabled_write_user_page(self):
        (rv, n, _) = init_cpu(f"""
            li x1, 0x54c01008
            li x2, 0xdeadbeef
            sw x2, 0(x1)
        """)

        # Create a pte for a supervisor page and a user page. Assert that the user page can
        # *write* from the supervisor code when the sum bit is set.

        page_table_address = 0x20001000
        rv.state.satp = (1 << 31) | (0 << 22) | (page_table_address >> 12)
        rv.state.sstatus = (1 << 18) # SUM bit sete
        rv.state.current_mode = PrivMode.Supervisor
        rv.state.pc = 0x55000000 # VPN[0] = 0x000, VPN[1] = 0x154, offset = 0x000

        vpn1 = 0x154
        pte = create_pte(v=1, r=1, x=1, g=1, a=1, ppn1=0x200) # corresponds to the 0x20000000 superpage
        rv.ram_write32(page_table_address + (vpn1 * 4), pte)

        # User target address: 0x20101008
        vpn1 = 0x153
        pte = create_pte(v=1, w=1, r=1, u=1, g=1, a=1, ppn1=0x201) # corresponds to the 0x20100000 superpage
        rv.ram_write32(page_table_address + (vpn1 * 4), pte)

        for _ in range(n):
            rv.fetch_decode_execute()

        # mem_value = struct.unpack_from("<I", rv.mem, 0x101008)[0]
        mem_value = rv.ram_read32(0x20101008)

        self.assertEqual(rv.state.current_mode, PrivMode.Supervisor)
        self.assertEqual(mem_value, 0xdeadbeef)

if __name__ == "__main__":
    unittest.main()
