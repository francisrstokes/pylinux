OUTPUT_ARCH("riscv")
ENTRY(_start)

PROVIDE(_max_program_size = 64m);

MEMORY
{
    ram (rwx) : ORIGIN = 0x20000000, LENGTH = 0x4000000
}

PROVIDE(_estack = ORIGIN(ram) + LENGTH(ram));

SECTIONS
{
    .text :
    {
        . = ALIGN(4);

        KEEP(*(.reset_vector .reset_vector.*));
        _svector = .;
        *(.vectortable .vectortable.*);
        _evector = .;

        KEEP(*(.init));
        *(.text .text.*);

        _srodata = .;
        *(.srodata .srodata.*);
        *(.rodata .rodata.*);
        _erodata = .;
        PROVIDE(_program_end = .);
    } > ram

    .data :/* ALIGN(4) */
    {
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
        _end = .;
    } > ram
}
