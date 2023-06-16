import os
import re
import subprocess
from typing import Dict
from tempfile import NamedTemporaryFile

RV_PREFIX="/opt/riscv32i/bin/riscv32-unknown-elf-"

def run_command(command: str):
    subprocess.call(command.split(" "))

def run_command_with_output(command: str):
    proc = subprocess.Popen(command.split(" "), stdout=subprocess.PIPE)
    output = proc.stdout.read()
    proc.communicate()
    return output

def parse_symbols(elf_filename: str):
    symbol_re = r"([0-9a-fA-F]+)\s(?:T|t)\s(.+)"
    raw_symbols = run_command_with_output(f"{RV_PREFIX}nm {elf_filename}").decode("utf-8").splitlines()
    symbols = {}
    for raw_line in raw_symbols:
        result = re.search(symbol_re, raw_line)
        if result is not None:
            (symbol_name, addr) = result.group(2, 1)
            symbols[symbol_name] = int(addr, 16)
    return symbols

def parse_instructions(raw_objdump: str):
    def is_symbol_line(line: str):
        symbol_line_re = r"^[0-9a-fA-F]+\s<[a-zA-Z0-9_]+>:$"
        return bool(re.match(symbol_line_re, line))

    def is_blank_line(line: str):
        return line.strip() == ""

    def read_instruction_data(line: str):
        instr_line_re = r"^([0-9a-fA-F]+):\s+[0-9a-fA-F]+\s+(.+)$"
        m = re.match(instr_line_re, line)
        if m is not None:
            return m.group(1, 2)
        raise Exception(f"Not an instruction line: {line}")

    lines = raw_objdump.split("Disassembly of section .text:")[1].strip().splitlines()
    instructions = {}
    for line in lines:
        if not is_symbol_line(line) and not is_blank_line(line):
            (addr, instr) = read_instruction_data(line)
            instructions[int(addr, 16)] = instr
    return instructions

preamble = ".section .text\n.global _start\n_start:"
linker_script = os.path.dirname(os.path.abspath(__file__)) + f"/../test/link.ld"

class RvAsm:
    raw: bytearray
    symbols: Dict[str, int]
    instructions: Dict[int, str]

    def __init__(self, asm_code: str, show_elf_path=False, show_objdump=False):
        asm_file = NamedTemporaryFile("w", delete=False)
        asm_file.write(preamble)
        asm_file.write(asm_code)
        asm_file.close()

        # Required for gcc to understand the file is assembly
        os.rename(asm_file.name, f"{asm_file.name}.S")

        run_command(f"{RV_PREFIX}gcc -march=rv32ima -mabi=ilp32 -nostdlib -nostartfiles -T {linker_script} {asm_file.name}.S -o {asm_file.name}.o")
        run_command(f"{RV_PREFIX}objcopy -O binary {asm_file.name}.o {asm_file.name}.bin")

        self.symbols = parse_symbols(f"{asm_file.name}.o")

        if show_elf_path:
            print(f"{asm_file.name}.o")

        raw_objdump = run_command_with_output(f"{RV_PREFIX}objdump -d {asm_file.name}.o").decode("utf-8")
        self.instructions = parse_instructions(raw_objdump)
        if show_objdump:
            print(raw_objdump)

        with open(f"{asm_file.name}.bin", "rb") as f:
            self.raw = f.read()
            f.close()

    def print_instruction(self, pc: int):
        if pc in self.instructions:
            print(f"[{pc:08x}] {self.instructions[pc]}")
        else:
            print(f"[{pc:08x}]  <unknown>")