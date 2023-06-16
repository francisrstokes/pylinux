from typing import List, TextIO
from enum import IntEnum
import struct
import sys

from asm import dump_source_and_dis

# TODO:
#   - Atomics tests
#   - More extensive branching tests? e.g. Loops
#   - Mask writes to read-only fields in CSRs
#       - mip: MTIP
#       - mstatus: MPP when writing an invalid value

OPCODE_LUI          = 0b0110111
OPCODE_AUIPC        = 0b0010111
OPCODE_JAL          = 0b1101111
OPCODE_JALR         = 0b1100111
OPCODE_BRANCH       = 0b1100011
OPCODE_LOAD         = 0b0000011
OPCODE_STORE        = 0b0100011
OPCODE_ALU_IMM      = 0b0010011
OPCODE_ALU_REG      = 0b0110011
OPCODE_FENCE        = 0b0001111
OPCODE_SYSTEM       = 0b1110011
OPCODE_A_EXT        = 0b0101111

BRANCH_BEQ          = 0b000
BRANCH_BNE          = 0b001
BRANCH_BLT          = 0b100
BRANCH_BGE          = 0b101
BRANCH_BLTU         = 0b110
BRANCH_BGEU         = 0b111

MEMSIZE_B           = 0b00
MEMSIZE_H           = 0b01
MEMSIZE_W           = 0b10

ALU_ADD             = 0b000
ALU_SL              = 0b001
ALU_SLT             = 0b010
ALU_SLTU            = 0b011
ALU_XOR             = 0b100
ALU_SR              = 0b101
ALU_OR              = 0b110
ALU_AND             = 0b111

CSR_RW              = 0b01
CSR_RS              = 0b10
CSR_RC              = 0b11

M_EXT_FUNCT7        = 0b0000001
M_EXT_MUL           = 0b000
M_EXT_MULH          = 0b001
M_EXT_MULHSU        = 0b010
M_EXT_MULHU         = 0b011
M_EXT_DIV           = 0b100
M_EXT_DIVU          = 0b101
M_EXT_REM           = 0b110
M_EXT_REMU          = 0b111

A_EXT_LR_W          = 0b00010
A_EXT_SC_W          = 0b00011
A_EXT_AMOSWAP_W     = 0b00001
A_EXT_AMOADD_W      = 0b00000
A_EXT_AMOXOR_W      = 0b00100
A_EXT_AMOAND_W      = 0b01100
A_EXT_AMOOR_W       = 0b01000
A_EXT_AMOMIN_W      = 0b10000
A_EXT_AMOMAX_W      = 0b10100
A_EXT_AMOMINU_W     = 0b11000
A_EXT_AMOMAXU_W     = 0b11100

PAGE_SIZE           = 4096

CLINT_SPACE_START   = 0x11000000
CLINT_SPACE_END     = 0x1100c000
CLINT_MSIP          = 0x11000000
CLINT_MTIMECMP_LOW  = 0x11004000
CLINT_MTIMECMP_HIGH = 0x11004004
CLINT_MTIME_LOW     = 0x1100bff8
CLINT_MTIME_HIGH    = 0x1100bffc

U8250_SPACE_START   = 0x10000000
U8250_SPACE_END     = 0x10ffffff
U8250_TX            = 0x10000000
U8250_RX_DATA       = 0x10000000
U8250_RX_READY      = 0x10000005
U8250_LINE_CONTROL  = 0x10000014

U8250_LCR_THRE      = 0x20

ROM_START           = 0x00000000
ROM_END             = 0x00100000
RAM_START           = 0x20000000
RAM_END             = 0x23ffffff

RESET_VECTOR        = RAM_START

PTE_V               = 0
PTE_R               = 1
PTE_W               = 2
PTE_X               = 3
PTE_U               = 4
PTE_G               = 5
PTE_A               = 6
PTE_D               = 7

STATUS_SIE          = 1
STATUS_MIE          = 3
STATUS_SPIE         = 5
STATUS_MPIE         = 7
STATUS_SPP          = 8
STATUS_MPP          = 11

IE_SSIE             = 1
IE_MSIE             = 3
IE_STIE             = 5
IE_MTIE             = 7
IE_SEIE             = 9
IE_MEIE             = 11

IP_MSIP             = 3
IP_MTIP             = 7

"""
Memory map

+----------------+------------------+
|   0x00000000   |                  |
|        -       |     BootROM?     |
|   0x0fffffff   |                  |
+----------------+------------------+
|   0x10000000   |                  |
|        -       |     Serial       |
|   0x10ffffff   |                  |
+----------------+------------------+
|   0x11000000   |                  |
|        -       |    CLINT Impl    |
|   0x1100bfff   |                  |
+----------------+------------------+
|   0x20000000   |                  |
|        -       |      RAM         |
|   0x23ffffff   |                  |
+----------------+------------------+
|   0x24000000   |                  |
|        -       |     Unmapped     |
|   0xffffffff   |                  |
+----------------+------------------+
"""

def bit_slice(value: int, from_bit: int, to_bit: int):
    width = from_bit - to_bit + 1
    return ((value >> to_bit) & ((1 << width) - 1))

def bit(value: int, bit_index: int):
    return (value >> bit_index) & 1

def sign_extend32(bits: int, value: int):
    if value & (1 << (bits - 1)):
        return ((0xffffffff >> bits) << bits) | value
    return value

def sign_extend64(value: int):
    if value & 0x80000000:
        return 0xffffffff00000000 | value
    return value

def as_signed32(value: int):
    return int.from_bytes(value.to_bytes(4, 'little'), 'little', signed=True)

def as_unsigned32(value: int):
    if value >= 0:
        return value
    return (-value ^ 0xffffffff) + 1

def as_unsigned64(value: int):
    if value >= 0:
        return value
    return (-value ^ 0xffffffffffffffff) + 1

def constrain32(value: int):
    return value & 0xffffffff

def write_to_u64_offset(old_value: int, value: int, offset: int, word_size: int):
    mask = (1 << (8 * word_size)) - 1
    shift = offset * 8
    mask = (mask << shift) ^ 0xffffffffffffffff
    return (old_value & mask) | (value << shift)

def read_from_u64_offset(value: int, offset: int, word_size: int):
    mask = (1 << (8 * word_size)) - 1
    return (value >> (offset * 8)) & mask

class ABIReg(IntEnum):
    zero = 0
    ra = 1
    sp = 2
    gp = 3
    tp = 4
    t0 = 5
    t1 = 6
    t2 = 7
    s0 = 8
    fp = 8
    s1 = 9
    a0 = 10
    a1 = 11
    a2 = 12
    a3 = 13
    a4 = 14
    a5 = 15
    a6 = 16
    a7 = 17
    s2 = 18
    s3 = 19
    s4 = 20
    s5 = 21
    s6 = 22
    s7 = 23
    s8 = 24
    s9 = 25
    s10 = 26
    s11 = 27
    t3 = 28
    t4 = 29
    t5 = 30
    t6 = 31

class PrivMode(IntEnum):
    User       = 0
    Supervisor = 1
    Machine    = 3

class TrapCause(IntEnum):
    InstructionAddressMisaligned    = 0
    InstructionAccessFault          = 1
    IllegalInstruction              = 2
    Breakpoint                      = 3
    LoadAddressMisaligned           = 4
    LoadAccessFault                 = 5
    Store_AMOAddressMisaligned      = 6
    Store_AMOAccessFault            = 7
    EnvironmentCallFromUMode        = 8
    EnvironmentCallFromSMode        = 9
    EnvironmentCallFromMMode        = 11
    InstructionPageFault            = 12
    LoadPageFault                   = 13
    Store_AMOPageFault              = 15
    SupervisorSoftwareInterrupt     = 0x80000000 | 1
    MachineSoftwareInterrupt        = 0x80000000 | 3
    SupervisorTimerInterrupt        = 0x80000000 | 5
    MachineTimerInterrupt           = 0x80000000 | 7
    SupervisorExternalInterrupt     = 0x80000000 | 9
    MachineExternalInterrupt        = 0x80000000 | 11

class RVTrap(Exception):
    cause: TrapCause
    tval: int
    def __init__(self, cause: TrapCause, tval = 0):
        self.cause = cause
        self.tval = tval

class MemoryAccessCtx(IntEnum):
    Fetch = 0
    Read  = 1
    Write = 2

class RVState:
    regs: List[int]
    pc: int

    # Atomic Extension
    reservation_address: int

    # Machine mode registers
    cyclel: int
    cycleh: int
    mstatus: int
    mscratch: int
    mhartid: int
    mtvec: int
    mie: int
    mip: int
    mepc: int
    mtval: int
    mcause: int
    medeleg: int
    mideleg: int

    mtimecmp: int

    # Supervisor registers
    sstatus: int
    sscratch: int
    stvec: int
    sie: int
    sip: int
    sepc: int
    stval: int
    scause: int
    satp: int

    # Additional internal state
    current_mode: PrivMode
    wait_for_interrupt: bool

    def __init__(self, pc):
        self.regs = [0] * 32
        self.pc = pc

        self.reservation_address = 0

        self.cycle = 0
        self.instret = 0
        self.mstatus = (PrivMode.Machine << STATUS_MPP)
        self.mscratch = 0
        self.mtvec = 0
        self.mhartid = 0
        self.mie = 0
        self.mip = 0
        self.mepc = 0
        self.mtval = 0
        self.mcause = 0
        self.medeleg = 0
        self.mideleg = 0
        self.sstatus = 0
        self.sscratch = 0
        self.stvec = 0
        self.sie = 0
        self.sip = 0
        self.sepc = 0
        self.stval = 0
        self.scause = 0
        self.satp = 0
        self.scounteren = 0

        self.mtimecmp = 0

        self.current_mode = PrivMode.Machine
        self.wait_for_interrupt = False

    def dump(self, cycle=True):
        modes = {
            PrivMode.Machine: "M",
            PrivMode.Supervisor: "S",
            PrivMode.User: "U",
        }

        print(f"mode:\t{modes[self.current_mode]}\tpc:\t{self.pc:08x}")

        if cycle:
            print(f"cycle:\t{self.cycle}\tmtimecmp:\t{self.mtimecmp}")

        abi_reg_pairs = [(x.name, x.value) for x in ABIReg]

        reg = 0
        while reg < 32:
            line = ""
            for i in range(8):
                abi_reg = abi_reg_pairs[reg+i]
                line += f"{abi_reg[0]}: {self.regs[abi_reg[1]]:08x}\t"
            reg += 8
            print(line)
        print()


# rv32ima
class RISCV:
    state: RVState
    mem: bytearray
    rom: bytearray

    breakpoints: List[int]

    console: TextIO
    uart_rx_buffer: List[int]

    def __init__(self, ram_size: int, pc = 0x80000000, console = sys.stdout, elf_path = None, gdb_mode = False):
        rom_size = 1024 * 1024 # 1MiB
        self.state = RVState(pc)
        self.mem = bytearray([0] * ram_size)
        self.rom = bytearray([0] * rom_size)
        self.breakpoints = []
        self.uart_rx_buffer = []
        self.console = console
        self.elf_path = elf_path
        self.gdb_mode = gdb_mode
        self.gdb_breakpoint_hit = False

        self.step_mode = False

    def dump_mem(self, address: int, size: int):
        output = ""
        for i in range(size):
            value = self.memory_read8(address + i)
            if i % 4 == 0:
                output += " "
            if i % 16 == 0:
                output += f"\n{(address + i):08x}: "
            output += f"{value:02x} "
        print(output.strip())

    def dump_source_line(self):
        if not self.elf_path:
            return
        print(dump_source_and_dis(self.elf_path, self.state.pc))

    def uart_push_rx_byte(self, byte_value: int):
        self.uart_rx_buffer.append(byte_value)

    def uart_consume_rx_byte(self):
        if len(self.uart_rx_buffer) > 0:
            byte_value = self.uart_rx_buffer[0]
            self.uart_rx_buffer = self.uart_rx_buffer[1:]
            return byte_value
        return 0

    def set_breakpoint(self, address: int):
        self.breakpoints.append(address)

    def get_trap_offset(self, mode: PrivMode, cause: TrapCause):
        tvec = self.state.mtvec if mode == PrivMode.Machine else self.state.stvec
        if (tvec & 3) == 0:
            return tvec & 0xfffffffc
        offset = 48 if (cause & 0x80000000) else 0
        return (tvec & 0xfffffffc) + offset + (4 * (cause & 0x7fffffff))

    def mm_address_in_ram(self, address: int):
        return address >= RAM_START and address <= RAM_END

    def mm_address_in_rom(self, address: int):
        return address >= ROM_START and address <= ROM_END

    def mm_address_in_clint_space(self, address: int):
        return address >= CLINT_SPACE_START and address <= CLINT_SPACE_END

    def mm_address_in_uart_space(self, address: int):
        return address >= U8250_SPACE_START and address <= U8250_SPACE_END

    def mm_handle_u8250_read(self, address: int):
        if address == U8250_RX_READY:
            return 0x60 | (1 if len(self.uart_rx_buffer) > 0 else 0)
        elif address == U8250_RX_DATA:
            return self.uart_consume_rx_byte()
        elif address == U8250_LINE_CONTROL:
            return U8250_LCR_THRE
        else:
            print(f"[mm_handle_u8250_read] Unknown address: {hex(address)}")
            return 0

    def mm_handle_u8250_write(self, address: int, value: int):
        if address == U8250_TX:
            c = chr(value & 0xff)
            self.console.write(c)
            self.console.flush()

    def mm_handle_clint_read(self, address: int, word_size: int):
        base_register_addr = (address & 0xffffff00)
        if base_register_addr == CLINT_MSIP:
            return bit(self.state.mip, IP_MSIP)
        elif base_register_addr == (CLINT_MTIME_LOW & 0xffffff00):
            offset = address - CLINT_MTIME_LOW
            return read_from_u64_offset(self.state.cycle, offset, word_size)
        elif base_register_addr == (CLINT_MTIMECMP_LOW & 0xffffff00):
            offset = address - CLINT_MTIMECMP_LOW
            return read_from_u64_offset(self.state.mtimecmp, offset, word_size)
        else:
            raise RVTrap(TrapCause.IllegalInstruction)

    def mm_handle_clint_write(self, address: int, value: int, word_size: int):
        base_register_addr = (address & 0xffffff00)
        if base_register_addr == CLINT_MSIP:
            if value > 0:
                self.state.mip |= (1 << IP_MSIP)
            else:
                self.state.mip &= (1 << IP_MSIP) ^ 0xffffffff
        elif base_register_addr == (CLINT_MTIMECMP_LOW & 0xffffff00):
            offset = address - CLINT_MTIMECMP_LOW
            self.state.mtimecmp = write_to_u64_offset(self.state.mtimecmp, value, offset, word_size)
            self.state.mip &= (1 << IP_MTIP) ^ 0xffffffff
        else:
            raise RVTrap(TrapCause.IllegalInstruction)

    def mmu_get_trap_value(self, address: int, access_ctx: MemoryAccessCtx):
        if access_ctx == MemoryAccessCtx.Fetch:
            cause = TrapCause.InstructionPageFault
        elif access_ctx == MemoryAccessCtx.Read:
            cause = TrapCause.LoadPageFault
        else:
            cause = TrapCause.Store_AMOPageFault
        return RVTrap(cause, address)

    """
    The `satp` register holds the PPN (physical page number, i.e. 4KiB block index) of the page table root.
    Page table entries are 32-bit words, where bits [31:10] describe a PPN, bits [9:8] are reserved for supervisor
    software, and bits [7:0] are flags describing properties of the page.
    In Sv32, the page table is a two-level radix tree. When a virtual address is being translated, the VPN
    (virtual page number) is divided into two 10-bit components: VPN[1] and VPN[0]. VPN[1] is used to index into the
    page table at the address specified by `satp`. If the entry has `r=0` and `x=0`, this entry points to the next level
    of the page table. The PPN specified in this entry is used as the new root page table, and VPN[0] is used to locate
    the page table entry. Assuming no faults, the next computed entry should now be a leaf, and contain the PPN of the
    actual mapped page. The offset component of the virtual address can now used to compute the true physical address.
    """
    def mmu_translate_address(self, address: int, access_ctx: MemoryAccessCtx):
        if self.state.current_mode == PrivMode.Machine:
            # In machine mode, fetches are never translated
            if access_ctx == MemoryAccessCtx.Fetch:
                return address

            # If MPP is set to supervisor, and MPRV is enabled, then reads and writes are also translated
            # in M-Mode
            if not (bool(self.state.satp & 0x80000000) and
                    bit(self.state.mstatus, 17) == 1 and
                    bit_slice(self.state.mstatus, 12, 11) == 1):
                return address
        elif self.state.current_mode == PrivMode.Supervisor and not bool(self.state.satp & 0x80000000):
            return address

        page_table_addr = bit_slice(self.state.satp, 21, 0) * PAGE_SIZE
        translation_level = 1

        vpns = [
            bit_slice(address, 21, 12),
            bit_slice(address, 31, 22)
        ]
        page_offset = bit_slice(address, 11, 0)

        while True:
            if translation_level < 0:
                raise self.mmu_get_trap_value(address, access_ctx)

            page_table_entry_address = page_table_addr + (vpns[translation_level] * 4)

            if not self.mm_address_in_ram(page_table_entry_address):
                raise self.mmu_get_trap_value(address, access_ctx)

            page_table_entry = struct.unpack_from("<I", self.mem, page_table_entry_address - RAM_START)[0]

            # Valid PTE?
            if bit(page_table_entry, PTE_V) == 0:
                raise self.mmu_get_trap_value(address, access_ctx)

            # Sensible permissions?
            if bit(page_table_entry, PTE_R) == 0 and bit(page_table_entry, PTE_W) == 1:
                raise self.mmu_get_trap_value(address, access_ctx)

            # Is this PTE a parent node?
            if bit(page_table_entry, PTE_R) == 0 and bit(page_table_entry, PTE_X) == 0:
                page_table_addr = bit_slice(page_table_entry, 31, 10) * PAGE_SIZE
                translation_level -= 1
                continue

            # Otherwise this must be a valid entry, check that the current context has permission
            # to access this page
            sum_bit = bit(self.state.sstatus, 18)
            user_bit = bit(page_table_entry, PTE_U)

            has_privilege =                  (self.state.current_mode == PrivMode.Machine)
            has_privilege = has_privilege or (self.state.current_mode == PrivMode.Supervisor and (not user_bit or sum_bit))
            has_privilege = has_privilege or (self.state.current_mode == PrivMode.User and user_bit)

            access_matches =                   (access_ctx == MemoryAccessCtx.Fetch and bit(page_table_entry, PTE_X))
            access_matches = access_matches or (access_ctx == MemoryAccessCtx.Read and bit(page_table_entry, PTE_R))
            access_matches = access_matches or (access_ctx == MemoryAccessCtx.Write and bit(page_table_entry, PTE_W))

            if not (has_privilege and access_matches):
                raise self.mmu_get_trap_value(address, access_ctx)

            # Translation successful, stop walking the table
            break

        # Superpages are leaf nodes that occur in the first level of translation. They allow mapping
        # a 4MiB region of memory with a single page entry (instead of 4KiB) by using 10 extra of the
        # virtual address directly in the calculation of the PPN (beyond the page offset).
        is_superpage = translation_level == 1

        physical_address = page_offset
        physical_address |= vpns[0] << 12 if is_superpage else bit_slice(page_table_entry, 19, 10) << 12
        physical_address |= bit_slice(page_table_entry, 31, 20) << 20

        return physical_address

    def load_rom(self, program: bytearray, offset: int):
        self.rom[offset:offset+len(program)] = program

    def load(self, program: bytearray, offset: int):
        self.mem[offset:offset+len(program)] = program

    def rom_read8(self, address: int):
        return self.rom[address - ROM_START]

    def rom_read16(self, address: int):
        return struct.unpack_from("<H", self.rom, address - ROM_START)[0]

    def rom_read32(self, address: int):
        return struct.unpack_from("<I", self.rom, address - ROM_START)[0]

    def ram_read8(self, address: int):
        return self.mem[address - RAM_START]

    def ram_read16(self, address: int):
        return struct.unpack_from("<H", self.mem, address - RAM_START)[0]

    def ram_read32(self, address: int):
        return struct.unpack_from("<I", self.mem, address - RAM_START)[0]

    def ram_write8(self, address: int, value: int):
        address -= RAM_START
        self.mem[address] = value

    def ram_write16(self, address: int, value: int):
        address -= RAM_START
        struct.pack_into("<H", self.mem, address, value)

    def ram_write32(self, address: int, value: int):
        address -= RAM_START
        struct.pack_into("<I", self.mem, address, value)

    def memory_read8(self, address: int) -> int:
        translated_address = self.mmu_translate_address(address, MemoryAccessCtx.Read)
        if self.mm_address_in_rom(translated_address):
            return self.rom_read8(translated_address)
        elif self.mm_address_in_ram(translated_address):
            return self.ram_read8(translated_address)
        elif self.mm_address_in_clint_space(translated_address) and self.state.current_mode == PrivMode.Machine:
            return self.mm_handle_clint_read(translated_address, 1)
        elif self.mm_address_in_uart_space(translated_address):
            return self.mm_handle_u8250_read(translated_address)
        else:
            raise RVTrap(TrapCause.IllegalInstruction)

    def memory_read16(self, address: int) -> int:
        if address & 0b1:
            raise RVTrap(TrapCause.LoadAddressMisaligned, address)

        translated_address = self.mmu_translate_address(address, MemoryAccessCtx.Read)
        if self.mm_address_in_rom(translated_address):
            return self.rom_read16(translated_address)
        elif self.mm_address_in_ram(translated_address):
            return self.ram_read16(translated_address)
        elif self.mm_address_in_clint_space(translated_address) and self.state.current_mode == PrivMode.Machine:
            return self.mm_handle_clint_read(translated_address, 2)
        elif self.mm_address_in_uart_space(translated_address):
            return self.mm_handle_u8250_read(translated_address)
        else:
            raise RVTrap(TrapCause.IllegalInstruction)

    def memory_read32(self, address: int, is_fetch = False) -> int:
        translated_address = self.mmu_translate_address(address, MemoryAccessCtx.Fetch if is_fetch else  MemoryAccessCtx.Read)

        if self.mm_address_in_uart_space(translated_address):
            return self.mm_handle_u8250_read(translated_address)

        if address & 0b11:
            raise RVTrap(TrapCause.LoadAddressMisaligned, address)

        if self.mm_address_in_rom(translated_address):
            return self.rom_read32(translated_address)
        elif self.mm_address_in_ram(translated_address):
            return self.ram_read32(translated_address)
        elif self.mm_address_in_clint_space(translated_address) and self.state.current_mode == PrivMode.Machine:
            return self.mm_handle_clint_read(translated_address, 4)
        else:
            raise RVTrap(TrapCause.IllegalInstruction)

    def memory_write8(self, address: int, value: int):
        translated_address = self.mmu_translate_address(address, MemoryAccessCtx.Write)
        if self.mm_address_in_ram(translated_address):
            self.ram_write8(translated_address, value)
        elif self.mm_address_in_clint_space(translated_address) and self.state.current_mode == PrivMode.Machine:
            self.mm_handle_clint_write(translated_address, value, 1)
        elif self.mm_address_in_uart_space(translated_address):
            self.mm_handle_u8250_write(translated_address, value)
        else:
            raise RVTrap(TrapCause.IllegalInstruction)

    def memory_write16(self, address: int, value: int):
        if address & 1:
            raise RVTrap(TrapCause.Store_AMOAddressMisaligned, address)

        translated_address = self.mmu_translate_address(address, MemoryAccessCtx.Write)
        if self.mm_address_in_ram(translated_address):
            self.ram_write16(translated_address, value)
        elif self.mm_address_in_clint_space(translated_address) and self.state.current_mode == PrivMode.Machine:
            self.mm_handle_clint_write(translated_address, value, 2)
        elif self.mm_address_in_uart_space(translated_address):
            self.mm_handle_u8250_write(translated_address, value)
        else:
            raise RVTrap(TrapCause.IllegalInstruction)

    def memory_write32(self, address: int, value: int):
        translated_address = self.mmu_translate_address(address, MemoryAccessCtx.Write)

        if self.mm_address_in_uart_space(translated_address):
            self.mm_handle_u8250_write(translated_address, value)
            return

        if address & 0b11:
            raise RVTrap(TrapCause.Store_AMOAddressMisaligned, address)

        if self.mm_address_in_ram(translated_address):
            self.ram_write32(translated_address, value)
        elif self.mm_address_in_clint_space(translated_address) and self.state.current_mode == PrivMode.Machine:
            self.mm_handle_clint_write(translated_address, value, 4)
        else:
            raise RVTrap(TrapCause.IllegalInstruction)

    def fetch(self) -> int:
        if not (self.state.pc & 0b11) == 0:
            raise RVTrap(TrapCause.InstructionAddressMisaligned)

        instruction = self.memory_read32(self.state.pc, True)
        self.state.pc = constrain32(self.state.pc + 4)
        return instruction

    def csr_read(self, csr: int):
        permission_bits = bit_slice(csr, 9, 8)
        if permission_bits == 3 and not self.state.current_mode == PrivMode.Machine:
            raise RVTrap(TrapCause.IllegalInstruction)
        elif permission_bits == 2 and not self.state.current_mode in [PrivMode.Machine, PrivMode.Supervisor]:
            raise RVTrap(TrapCause.IllegalInstruction)

        if csr == 0xf14:
            return self.state.mhartid
        elif csr == 0x340:
            return self.state.mscratch
        elif csr == 0x302:
            return self.state.medeleg
        elif csr == 0x303:
            return self.state.mideleg
        elif csr == 0x305:
            return self.state.mtvec
        elif csr == 0x304:
            return self.state.mie
        elif csr == 0xC00:
            return self.state.cyclel
        elif csr == 0x344:
            return self.state.mip
        elif csr == 0x341:
            return self.state.mepc
        elif csr == 0x300:
            return self.state.mstatus
        elif csr == 0x342:
            return self.state.mcause
        elif csr == 0x343:
            return self.state.mtval
        elif csr == 0x140:
            return self.state.sscratch
        elif csr == 0x105:
            return self.state.stvec
        elif csr == 0x104:
            return self.state.sie
        elif csr == 0x144:
            return self.state.sip
        elif csr == 0x141:
            return self.state.sepc
        elif csr == 0x100:
            return self.state.sstatus
        elif csr == 0x142:
            return self.state.scause
        elif csr == 0x143:
            return self.state.stval
        elif csr == 0x180:
            return self.state.satp
        elif csr in [0xb00, 0xc00, 0xc01]:
            return self.state.cycle & 0xffffffff
        elif csr in [0xb80, 0xc80, 0xc81]:
            return (self.state.cycle >> 32) & 0xffffffff
        elif csr in [0xb02, 0xc02]:
            return self.state.instret & 0xffffffff
        elif csr in [0xb82, 0xc82]:
            return (self.state.instret >> 32) & 0xffffffff
        elif csr == 0xf11:
            return 0x00000000        # mvendorid
        elif csr == 0x301:
            return 0x40141101        # misa (XLEN=32, IMASU)
        elif csr in [0xf12, 0xf13]:
            return 0                 # marchid, mimpid
        else:
            # print(f"csr: {csr:03X}")
            raise RVTrap(TrapCause.IllegalInstruction, csr)

    def csr_write(self, csr: int, value: int):
        permission_bits = bit_slice(csr, 9, 8)
        if permission_bits == 3 and not self.state.current_mode == PrivMode.Machine:
            raise RVTrap(TrapCause.IllegalInstruction)
        elif permission_bits == 2 and not self.state.current_mode in [PrivMode.Machine, PrivMode.Supervisor]:
            raise RVTrap(TrapCause.IllegalInstruction)

        read_only_csrs = [
            0xf14, 0xb00, 0xc00, 0xc01,
            0xb80, 0xc80, 0xc81, 0xb02,
            0xc02, 0xb82, 0xc82, 0xf11,
            0x301
        ]

        if csr in read_only_csrs:
            pass
        elif csr == 0x340:
            self.state.mscratch = value
        elif csr == 0x302:
            self.state.medeleg = value
        elif csr == 0x303:
            self.state.mideleg = value
        elif csr == 0x305:
            self.state.mtvec = value
        elif csr == 0x304:
            self.state.mie = value
        elif csr == 0x344:
            self.state.mip = value
        elif csr == 0x341:
            self.state.mepc = value
        elif csr == 0x300:
            self.state.mstatus = value
        elif csr == 0x342:
            self.state.mcause = value
        elif csr == 0x343:
            self.state.mtval = value
        elif csr == 0x140:
            self.state.sscratch = value
        elif csr == 0x105:
            self.state.stvec = value
        elif csr == 0x104:
            self.state.sie = value
        elif csr == 0x144:
            self.state.sip = value
        elif csr == 0x141:
            self.state.sepc = value
        elif csr == 0x100:
            self.state.sstatus = value
        elif csr == 0x142:
            self.state.scause = value
        elif csr == 0x143:
            self.state.stval = value
        elif csr == 0x180:
            self.state.satp = value
        else:
            raise RVTrap(TrapCause.IllegalInstruction, csr)

    def handle_trap(self, trap: RVTrap):
        # All traps end up in M-Mode by default, but can be redirected according to the contents of the mXdeleg register
        is_interrupt = bool(trap.cause & 0x80000000)
        deleg = self.state.mideleg if is_interrupt else self.state.medeleg

        # A trap occuring in a higher privledge mode must not transfer control to a lower privledge mode (3.1.8)
        delegate_to_supervisor = bool(deleg & (1 << (trap.cause & 0xffff))) and self.state.current_mode != PrivMode.Machine
        effective_mode = PrivMode.Supervisor if delegate_to_supervisor else PrivMode.Machine

        status = self.state.mstatus if effective_mode == PrivMode.Machine else self.state.sstatus

        if is_interrupt:
            ie = self.state.mie if effective_mode == PrivMode.Machine else self.state.sie
            mie = bit(status, STATUS_MIE)
            sie = bit(status, STATUS_SIE)
            msie = bit(ie, IE_MSIE)
            ssie = bit(ie, IE_SSIE)
            mtie = bit(ie, IE_MTIE)
            stie = bit(ie, IE_STIE)
            meie = bit(ie, IE_MEIE)
            seie = bit(ie, IE_SSIE)

            if effective_mode == PrivMode.Machine and mie == 0:
                return False
            if effective_mode == PrivMode.Supervisor and sie == 0:
                return False

            if trap.cause == TrapCause.SupervisorSoftwareInterrupt and ssie == 0:
                return False
            elif trap.cause == TrapCause.MachineSoftwareInterrupt and msie == 0:
                return False
            elif trap.cause == TrapCause.SupervisorTimerInterrupt and stie == 0:
                return False
            elif trap.cause == TrapCause.MachineTimerInterrupt and mtie == 0:
                return False
            elif trap.cause == TrapCause.SupervisorExternalInterrupt and seie == 0:
                return False
            elif trap.cause == TrapCause.MachineExternalInterrupt and meie == 0:
                return False

            self.state.wait_for_interrupt = False

        if not delegate_to_supervisor:
            self.state.mcause = trap.cause
            self.state.mepc = self.state.pc # TODO: Check if this needs to just be pc for an exception
            self.state.mtval = trap.tval

            mie = bit(self.state.mstatus, STATUS_MIE)

            # Clear the bits we need to update in the register
            self.state.mstatus &= 0xffffe766
            self.state.mstatus |= mie << STATUS_MPIE
            self.state.mstatus |= self.state.current_mode << STATUS_MPP
        else:
            self.state.scause = trap.cause
            self.state.sepc = self.state.pc
            self.state.stval = trap.tval

            sie = bit(self.state.mstatus, STATUS_SIE)

            # Clear the bits we need to update in the register
            self.state.sstatus &= 0xfffffecc
            self.state.sstatus |= sie << STATUS_SPIE
            self.state.sstatus |= self.state.current_mode << STATUS_SPP

        self.state.current_mode = effective_mode
        self.state.pc = self.get_trap_offset(effective_mode, trap.cause)

    def check_for_interrupts(self):
        # Set interrupt pending bits
        if self.state.cycle >= self.state.mtimecmp:
            self.state.mip |= (1 << IP_MTIP)

        # Check for enabled and pending interrupts
        if bit(self.state.mstatus, STATUS_MIE):
            if bit(self.state.mie, TrapCause.MachineTimerInterrupt & 0xffff) and bit(self.state.mip, IP_MTIP):
                self.state.mip &= (1 << IP_MTIP) ^ 0xffffffff
                raise RVTrap(TrapCause.MachineTimerInterrupt)
            if bit(self.state.mie, TrapCause.MachineSoftwareInterrupt & 0xffff) and bit(self.state.mip, IP_MSIP):
                self.state.mip &= (1 << IP_MSIP) ^ 0xffffffff
                raise RVTrap(TrapCause.MachineSoftwareInterrupt)

    def fetch_decode_execute(self):
        if self.step_mode or self.state.pc in self.breakpoints:
            self.state.dump()
            # self.dump_source_line()
            breakpoint()

        try:
            self.gdb_breakpoint_hit = False
            self.check_for_interrupts()

            if not self.state.wait_for_interrupt:
                instruction = self.fetch()

                opcode = bit_slice(instruction, 6, 0)
                rd = bit_slice(instruction, 11, 7)
                funct3 = bit_slice(instruction, 14, 12)
                rs1 = bit_slice(instruction, 19, 15)
                rs2 = bit_slice(instruction, 24, 20)

                if instruction == 0x10500073:
                    # WFI
                    self.state.wait_for_interrupt = True
                elif instruction == 0x30200073:
                    # MRET
                    mpp = (self.state.mstatus >> STATUS_MPP) & 3
                    mpie = bit(self.state.mstatus, STATUS_MPIE)

                    self.state.mstatus &= 0xffffe766
                    self.state.mstatus |= mpie << STATUS_MIE
                    self.state.mstatus |= mpp << STATUS_MPP

                    self.state.pc = self.state.mepc
                    self.state.current_mode = mpp
                elif instruction == 0x10200073:
                    # SRET
                    spp = (self.state.sstatus >> STATUS_SPP)
                    spie = bit(self.state.sstatus, STATUS_SPIE)

                    self.state.sstatus &= 0xfffffedd
                    self.state.sstatus |= spie << STATUS_SIE
                    self.state.sstatus |= spp << STATUS_SPP

                    self.state.pc = self.state.sepc
                    self.state.current_mode = spp
                elif instruction == 0x00200073:
                    # URET
                    raise RVTrap(TrapCause.IllegalInstruction)
                elif opcode == OPCODE_LUI:
                    imm = bit_slice(instruction, 31, 12)
                    if rd != 0:
                        self.state.regs[rd] = imm << 12
                elif opcode == OPCODE_AUIPC:
                    imm = bit_slice(instruction, 31, 12)
                    if rd != 0:
                        self.state.regs[rd] = constrain32(self.state.pc + (imm << 12) - 4)
                elif opcode == OPCODE_JAL:
                    imm = sign_extend32(21,
                                        (bit(instruction, 31)           << 20) |
                                        (bit_slice(instruction, 19, 12) << 12) |
                                        (bit(instruction, 20)           << 11) |
                                        (bit_slice(instruction, 30, 21) << 1))
                    rd_value = self.state.pc if rd != 0 else self.state.regs[rd]
                    self.state.pc = constrain32(self.state.pc + imm - 4)
                    self.state.regs[rd] = rd_value
                elif opcode == OPCODE_JALR and funct3 == 0b000:
                    imm = sign_extend32(12, bit_slice(instruction, 31, 20))

                    rd_value = self.state.pc if rd != 0 else self.state.regs[rd]
                    self.state.pc = (self.state.regs[rs1] + imm) & 0xfffffffe
                    self.state.regs[rd] = rd_value
                elif opcode == OPCODE_BRANCH:
                    imm = sign_extend32(13, ((bit(instruction, 31)          << 12) |
                                            (bit(instruction, 7)            << 11) |
                                            (bit_slice(instruction, 30, 25) << 5) |
                                            (bit_slice(instruction, 11, 8)  << 1)
                                            ))

                    take_branch =                (funct3 == BRANCH_BEQ and self.state.regs[rs1] == self.state.regs[rs2])
                    take_branch = take_branch or (funct3 == BRANCH_BNE and self.state.regs[rs1] != self.state.regs[rs2])
                    take_branch = take_branch or (funct3 == BRANCH_BGE and as_signed32(self.state.regs[rs1]) >= as_signed32(self.state.regs[rs2]))
                    take_branch = take_branch or (funct3 == BRANCH_BLT and as_signed32(self.state.regs[rs1]) < as_signed32(self.state.regs[rs2]))
                    take_branch = take_branch or (funct3 == BRANCH_BGEU and self.state.regs[rs1] >= self.state.regs[rs2])
                    take_branch = take_branch or (funct3 == BRANCH_BLTU and self.state.regs[rs1] < self.state.regs[rs2])

                    # TODO: check for funct3 validity, and trap otherwise

                    if take_branch:
                        self.state.pc = constrain32(self.state.pc + imm - 4)
                elif opcode == OPCODE_LOAD:
                    imm = sign_extend32(12, bit_slice(instruction, 31, 20))
                    address = constrain32(self.state.regs[rs1] + imm)

                    should_sign_extend = (funct3 & 0b100) == 0
                    loaded_value = 0

                    if (funct3 & 0b011) == MEMSIZE_B:
                        loaded_value = self.memory_read8(address)
                        if should_sign_extend:
                            loaded_value = sign_extend32(8, loaded_value)
                    elif (funct3 & 0b011) == MEMSIZE_H:
                        loaded_value = self.memory_read16(address)
                        if should_sign_extend:
                            loaded_value = sign_extend32(16, loaded_value)
                    elif (funct3 & 0b011) == MEMSIZE_W:
                        loaded_value = self.memory_read32(address)

                    if rd != 0:
                        self.state.regs[rd] = loaded_value
                elif opcode == OPCODE_STORE:
                    imm = sign_extend32(12, (bit_slice(instruction, 31, 25) << 5) | bit_slice(instruction, 11, 7))
                    address = constrain32(self.state.regs[rs1] + imm)

                    if (funct3 & 0b011) == MEMSIZE_B:
                        self.memory_write8(address, self.state.regs[rs2] & 0xff)
                    elif (funct3 & 0b011) == MEMSIZE_H:
                        self.memory_write16(address, self.state.regs[rs2] & 0xffff)
                    elif (funct3 & 0b011) == MEMSIZE_W:
                        self.memory_write32(address, self.state.regs[rs2])
                elif opcode == OPCODE_ALU_IMM:
                    imm = sign_extend32(12, bit_slice(instruction, 31, 20))
                    shamt = rs2
                    is_arithmetic = bit(instruction, 30)

                    if rd != 0:
                        if funct3 == ALU_ADD:
                            self.state.regs[rd] = constrain32(imm + self.state.regs[rs1])
                        elif funct3 == ALU_SLT:
                            self.state.regs[rd] = int(as_signed32(self.state.regs[rs1]) < as_signed32(imm))
                        elif funct3 == ALU_SLTU:
                            self.state.regs[rd] = int(self.state.regs[rs1] < imm)
                        elif funct3 == ALU_XOR:
                            self.state.regs[rd] = constrain32(self.state.regs[rs1] ^ imm)
                        elif funct3 == ALU_OR:
                            self.state.regs[rd] = self.state.regs[rs1] | imm
                        elif funct3 == ALU_AND:
                            self.state.regs[rd] = self.state.regs[rs1] & imm
                        elif funct3 == ALU_SL:
                            self.state.regs[rd] = constrain32(self.state.regs[rs1] << shamt)
                        elif funct3 == ALU_SR and is_arithmetic:
                            self.state.regs[rd] = constrain32(as_unsigned32(as_signed32(self.state.regs[rs1]) >> shamt))
                        elif funct3 == ALU_SR and not(is_arithmetic):
                            self.state.regs[rd] = constrain32(self.state.regs[rs1] >> shamt)
                        else:
                            raise RVTrap(TrapCause.IllegalInstruction)
                elif opcode == OPCODE_ALU_REG:
                    is_arithmetic = bit(instruction, 30)
                    is_m_ext = bit_slice(instruction, 31, 25) == M_EXT_FUNCT7

                    if rd != 0:
                        if is_m_ext:
                            if funct3 == M_EXT_MUL:
                                self.state.regs[rd] = constrain32(as_unsigned64(self.state.regs[rs1] * self.state.regs[rs2]))
                            elif funct3 == M_EXT_MULH:
                                self.state.regs[rd] = constrain32((self.state.regs[rs1] * self.state.regs[rs2]) >> 32)
                            elif funct3 == M_EXT_MULHSU:
                                self.state.regs[rd] = constrain32(as_unsigned64(sign_extend64(self.state.regs[rs1]) * self.state.regs[rs2]) >> 32)
                            elif funct3 == M_EXT_MULHU:
                                self.state.regs[rd] = (self.state.regs[rs1] * self.state.regs[rs2]) >> 32
                            elif funct3 == M_EXT_DIV:
                                if self.state.regs[rs2] == 0:
                                    self.state.regs[rd] = 0xffffffff
                                else:
                                    self.state.regs[rd] = as_unsigned32(as_signed32(self.state.regs[rs1]) // as_signed32(self.state.regs[rs2]))
                            elif funct3 == M_EXT_DIVU:
                                if self.state.regs[rs2] == 0:
                                    self.state.regs[rd] = 0xffffffff
                                else:
                                    self.state.regs[rd] = self.state.regs[rs1] // self.state.regs[rs2]
                            elif funct3 == M_EXT_REM:
                                if self.state.regs[rs2] == 0:
                                    self.state.regs[rd] = self.state.regs[rs1]
                                else:
                                    self.state.regs[rd] = as_unsigned32(as_signed32(self.state.regs[rs1]) % as_signed32(self.state.regs[rs2]))
                            elif funct3 == M_EXT_REMU:
                                if self.state.regs[rs2] == 0:
                                    self.state.regs[rd] = self.state.regs[rs1]
                                else:
                                    self.state.regs[rd] = as_unsigned32(self.state.regs[rs1] % self.state.regs[rs2])
                        elif funct3 == ALU_ADD and not is_arithmetic:
                            self.state.regs[rd] = constrain32(self.state.regs[rs1] + self.state.regs[rs2])
                        elif funct3 == ALU_ADD and is_arithmetic:
                            self.state.regs[rd] = constrain32(self.state.regs[rs1] - self.state.regs[rs2])
                        elif funct3 == ALU_SL:
                            self.state.regs[rd] = constrain32(self.state.regs[rs1] << (self.state.regs[rs2] & 0x1f))
                        elif funct3 == ALU_SLT:
                            self.state.regs[rd] = int(self.state.regs[rs1] < self.state.regs[rs2])
                        elif funct3 == ALU_SLTU:
                            self.state.regs[rd] = int(as_signed32(self.state.regs[rs1]) < as_signed32(self.state.regs[rs2]))
                        elif funct3 == ALU_XOR:
                            self.state.regs[rd] = constrain32(self.state.regs[rs1] ^ self.state.regs[rs2])
                        elif funct3 == ALU_SR and not(is_arithmetic):
                            self.state.regs[rd] = constrain32(self.state.regs[rs1] >> (self.state.regs[rs2] & 0x1f))
                        elif funct3 == ALU_SR and is_arithmetic:
                            self.state.regs[rd] = constrain32(as_unsigned32(as_signed32(self.state.regs[rs1]) >> (self.state.regs[rs2] & 0x1f)))
                        elif funct3 == ALU_OR:
                            self.state.regs[rd] = self.state.regs[rs1] | self.state.regs[rs2]
                        elif funct3 == ALU_AND:
                            self.state.regs[rd] = self.state.regs[rs1] & self.state.regs[rs2]
                elif opcode == OPCODE_FENCE:
                    # FENCE / FENCE.I
                    pass
                elif opcode == OPCODE_SYSTEM and bit_slice(instruction, 31, 7) == 0:
                    if self.state.current_mode == PrivMode.Machine:
                        raise RVTrap(TrapCause.EnvironmentCallFromMMode)
                    elif self.state.current_mode == PrivMode.Supervisor:
                        raise RVTrap(TrapCause.EnvironmentCallFromSMode)
                    else:
                        raise RVTrap(TrapCause.EnvironmentCallFromUMode)
                elif opcode == OPCODE_SYSTEM and bit_slice(instruction, 31, 25) == 0x09 and bit_slice(instruction, 14, 7) == 0:
                    # SFENCE.VMA
                    # No need to do anything here, as the emulator does not have any kind of TLB or other
                    # cache related to page tables. That might change in the future if performance is abismal, and
                    # the complexity of adding it is within the accepted parameters
                    pass
                elif opcode == OPCODE_SYSTEM and bit_slice(instruction, 31, 7) == 0x2000:
                    if not self.gdb_mode:
                        raise RVTrap(TrapCause.Breakpoint)
                    else:
                        self.gdb_breakpoint_hit = True
                        # GDB will rewrite the current instruction
                        # self.state.pc -= 4
                elif opcode == OPCODE_SYSTEM:
                    csr = bit_slice(instruction, 31, 20)
                    in_value = rs1 if (funct3 & 0b100) else self.state.regs[rs1]

                    # Always perform the read + side effects
                    csr_value = self.csr_read(csr)
                    if rd != 0:
                        self.state.regs[rd] = csr_value

                    if (funct3 & 0b011) == CSR_RW:
                        self.csr_write(csr, in_value)
                    elif (funct3 & 0b011) == CSR_RS:
                        self.csr_write(csr, self.csr_read(csr) | in_value)
                    elif (funct3 & 0b011) == CSR_RC:
                        self.csr_write(csr, self.csr_read(csr) & (in_value ^ 0xffffffff))
                elif opcode == OPCODE_A_EXT and funct3 == 0b010:
                    funct5 = bit_slice(instruction, 31, 27)
                    word = self.memory_read32(self.state.regs[rs1])
                    do_writeback = True
                    writeback_value = word
                    rd_value = word

                    if funct5 == A_EXT_LR_W:
                        self.state.reservation_address = self.state.regs[rs1]
                    elif funct5 == A_EXT_SC_W:
                        if not self.state.reservation_address == self.state.regs[rs1]:
                            do_writeback = False
                            rd_value = 1
                        else:
                            writeback_value = self.state.regs[rs2]
                            rd_value = 0
                    elif funct5 == A_EXT_AMOSWAP_W:
                        pass
                    elif funct5 == A_EXT_AMOADD_W:
                        writeback_value = constrain32(word + self.state.regs[rs2])
                    elif funct5 == A_EXT_AMOXOR_W:
                        writeback_value = constrain32(word ^ self.state.regs[rs2])
                    elif funct5 == A_EXT_AMOAND_W:
                        writeback_value = word & self.state.regs[rs2]
                    elif funct5 == A_EXT_AMOOR_W:
                        writeback_value = word | self.state.regs[rs2]
                    elif funct5 == A_EXT_AMOMIN_W:
                        writeback_value = self.state.regs[rs2] if as_signed32(self.state.regs[rs2]) < as_signed32(word) else word
                    elif funct5 == A_EXT_AMOMAX_W:
                        writeback_value = self.state.regs[rs2] if as_signed32(self.state.regs[rs2]) > as_signed32(word) else word
                    elif funct5 == A_EXT_AMOMINU_W:
                        writeback_value = self.state.regs[rs2] if self.state.regs[rs2] < word else word
                    elif funct5 == A_EXT_AMOMAXU_W:
                        writeback_value = self.state.regs[rs2] if self.state.regs[rs2] > word else word
                    else:
                        raise RVTrap(TrapCause.IllegalInstruction)

                    if do_writeback:
                        self.memory_write32(self.state.regs[rs1], writeback_value)

                    if rd != 0:
                        self.state.regs[rd] = rd_value
                else:
                    raise RVTrap(TrapCause.IllegalInstruction)

                # This is separate from the cycle counter, since a trap will inhibit an instruction
                # from completing
                self.state.instret += 1

        except RVTrap as trap:
            # print("Trap!")
            # print(trap)
            self.handle_trap(trap)

            # If the trap was an interrupt, we need early return and internally call fetch_decode_execute,
            # in order to make sure that timers are *not* advanced until an actual instruction runs
            if trap.cause & 0x80000000:
                return self.fetch_decode_execute()

        # Advance timers
        self.state.cycle += 1
