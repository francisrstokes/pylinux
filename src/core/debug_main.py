from riscv import RISCV, ABIReg
from gdbstub import GDBStub

import ctypes

rv = RISCV(64 * 1024 * 1024, 0x20000000, gdb_mode=True)

sbi_fw_path = "./opensbi-fw.bin"
sbi_elf_path = "./opensbi-fw.elf"
linux_image_path = "./buildroot/output/build/linux-6.3.6/arch/riscv/boot/Image"
dtb_path = "./device-tree.dtb"

sbi_fw_address = 0
with open(sbi_fw_path, "rb") as f:
    sbi_fw = f.read()
rv.load(sbi_fw, sbi_fw_address)

# Load the dtb, and place the address
dtb_load_address = 0x50000 # 320KiB after OpenSBI
with open(dtb_path, "rb") as f:
    dtb = f.read()
rv.load(dtb, dtb_load_address)
print(f"sizeof dtb: {len(dtb)}")

# After the DTB, place the fw_dynamic_info structure
class fw_dynamic_info_struct(ctypes.LittleEndianStructure):
    _fields_ = [("magic", ctypes.c_uint32),
                ("version", ctypes.c_uint32),
                ("next_addr", ctypes.c_uint32),
                ("next_mode", ctypes.c_uint32),
                ("options", ctypes.c_uint32)]

fw_dynamic_info = bytearray(fw_dynamic_info_struct(0x4942534f, 2, 0x20400000, 1, 0))
fw_dynamic_info_addr = dtb_load_address + len(dtb) + (8 - (len(dtb) & 0b111))
rv.load(fw_dynamic_info, fw_dynamic_info_addr)

linux_load_address = 0x00400000 # 0x20400000
with open(linux_image_path, "rb") as f:
    linux_image = f.read()
rv.load(linux_image, linux_load_address)

# Hart ID
rv.state.regs[ABIReg.a0] = 0
# DTB address should be in a1 when OpenSBI starts
rv.state.regs[ABIReg.a1] = 0x20000000 | dtb_load_address
rv.state.regs[ABIReg.a2] = 0x20000000 | fw_dynamic_info_addr

print(f"dtb addr: {rv.state.regs[ABIReg.a1]:08x}")
print(f"dyn info addr: {rv.state.regs[ABIReg.a2]:08x}")
print(f"linux kernel load addr: {0x20000000 | linux_load_address:08x}")

# Set the stack pointer
rv.state.regs[ABIReg.sp] = 0x23fffffc

# with open("./bare-metal/baremetal.bin", "rb") as f:
#     rv.load(f.read(), 0)

# rv.state.pc = rv.memory_read32(0x20000000)

gdb_stub = GDBStub(rv)
gdb_stub.start_server()
