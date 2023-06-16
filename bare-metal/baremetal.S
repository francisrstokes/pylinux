.section .reset_vector
.word _start

.section .text
.globl _start
_start:
  lla sp, 0x24000000
  lla gp, __global_pointer$
  j main
