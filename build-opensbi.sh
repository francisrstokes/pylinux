#!/bin/bash

RVGNU="/home/francis/repos/pylinux/buildroot/output/host/bin/riscv32-buildroot-linux-gnu-"
# LINUX_PAYLOAD="/home/francis/repos/pylinux//buildroot/output/images/Image"

# Note: First apply `opensbi-changes.patch` with `cd opensbi && git apply ../opensbi-changes.patch`
#       This patch includes the proper firmware start address, disabling compressed instructions,
#       and adding uart support. It's a janky way of doing it (vs building a proper platform), but it
#       works for now.

make -C opensbi clean

CROSS_COMPILE=$RVGNU \
PLATFORM=generic \
PLATFORM_RISCV_XLEN=32 \
PLATFORM_RISCV_ISA=rv32ima \
PLATFORM_RISCV_ABI=ilp32 \
FW_PIC=y \
FW_TEXT_START=0x20000000 \
DEBUG=1 \
make -C opensbi all

cp ./opensbi/build/platform/generic/firmware/fw_dynamic.bin ./opensbi-fw.bin
cp ./opensbi/build/platform/generic/firmware/fw_dynamic.elf ./opensbi-fw.elf

./buildroot/output/host/bin/riscv32-buildroot-linux-gnu-objdump -l -d opensbi-fw.elf > debug.txt
