PROJECT:=baremetal
TARGETS:=$(PROJECT).elf $(PROJECT).bin $(PROJECT).debug.txt

all : $(TARGETS)

PREFIX:=/opt/riscv32i/bin/riscv32-unknown-elf-
CFLAGS:=-fno-stack-protector
CFLAGS+=-static-libgcc -fdata-sections -ffunction-sections
CFLAGS+=-ggdb -O0 -march=rv32ima -mabi=ilp32 -static
# LDFLAGS:= -T link.ld -Wl,--gc-sections
LDFLAGS:= -T link.ld -nostdlib -Wl,--gc-sections

SRC_FILES += $(PROJECT).c
SRC_FILES += $(PROJECT).S

$(PROJECT).elf : $(SRC_FILES)
	$(PREFIX)gcc -o $@ $^ $(CFLAGS) $(LDFLAGS)

$(PROJECT).debug.txt : $(PROJECT).elf
	$(PREFIX)objdump -d $^ > $@
	$(PREFIX)objdump -S $^ >> $@

$(PROJECT).bin : $(PROJECT).elf
	$(PREFIX)objcopy $^ -O binary $@

test : $(PROJECT).bin
	../mini-rv32ima/mini-rv32ima -f $<

clean :
	rm -rf $(TARGETS)

