from ..core.riscv import RISCV
from ..core.asm import RvAsm

def init_cpu(asm_code: str, ram_size = 64 * 1024 * 1024, pc = 0x20000000, debug=False):
    rv = RISCV(ram_size, pc)
    program = RvAsm(asm_code, show_objdump=debug)
    rv.load(program.raw, 0)
    return (rv, len(program.raw) // 4, program.symbols)
