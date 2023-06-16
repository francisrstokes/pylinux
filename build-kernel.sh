#!/bin/bash

cd buildroot
make
cd ..
./buildroot/output/host/bin/riscv32-linux-objdump -d ./buildroot/output/build/linux-6.3.6/vmlinux > linux.dis
