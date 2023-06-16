OUTPUT_ARCH("riscv")
ENTRY(_start)

PROVIDE(_max_program_size = 1m);

MEMORY
{
    ram         (rwx) : ORIGIN = 0x20000000, LENGTH = 0x100000
}

SECTIONS
{
    .text : ALIGN(4)
    {
        /* Reset vector, pointing to the _start */
        *(.reset_vector .reset_vector.*);

        /* Vector Table */
        _svector = .;
        *(.vectortable .vectortable.*);
        _evector = .;

        KEEP(*(.init));
        /* Code */
        *(.text .text.*);

        /* Pack .rodata in boot ROM as well as .text as it's read-only */
        _srodata = .;
        *(.srodata .srodata.*);
        *(.rodata .rodata.*);
        _erodata = .;
        _program_end = .;
    } > ram

    .data :/* ALIGN(4) */
    {
        /* This should get set in the bootlaoder. Points to RAM + 2K, which is the range of immediates */
        PROVIDE( __global_pointer$ = . + (4K / 2) );

        _sdata = .;
        *(.sdata .sdata.* .sdata2 .sdata2.*);
        *(.data .data.*);

        . = ALIGN(4);
        _edata = .;
    } > ram

    .bss (NOLOAD) :
    {
        . = ALIGN(4);
        _sbss = .;
        *(.sbss .sbss.* .bss .bss.*);
        . = ALIGN(4);
        _ebss = .;
    } > ram
}
