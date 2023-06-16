from riscv import RISCV

import sys
import select
import tty
import termios

CYCLES_PER_ITERATION = 1000

# Read the bare metal image (build with `cd bare-metal && make`)
with open("./bare-metal/baremetal.bin", "rb") as f:
    baremetal_code = f.read()

rv = RISCV(64 * 1024 * 1024, 0x20000000)
rv.load(baremetal_code, 0)
n = len(baremetal_code) >> 2

# The first word in the image contains the reset vector
rv.state.pc = rv.ram_read32(0x20000000)

# Set the stack pointer
rv.state.regs[2] = 0x23fffffc

# Handle all of the IO/terminal operations externally
# The RISCV core class can be passed a `TextIO` serial console output,
# which can be mocked for testing
def data_available():
    return select.select([sys.stdin], [], [], 0) == ([sys.stdin], [], [])

old_settings = termios.tcgetattr(sys.stdin)
try:
    tty.setcbreak(sys.stdin.fileno())

    i = 0
    while True:
        for i in range(CYCLES_PER_ITERATION):
            rv.fetch_decode_execute()

        # UART data is pushed to an internal buffer
        if data_available():
            c = ord(sys.stdin.read(1))
            rv.uart_push_rx_byte(c)
finally:
    termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
