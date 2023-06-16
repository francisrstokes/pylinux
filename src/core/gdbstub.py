import socket
import select
from riscv import RISCV, RAM_START, RAM_END, ROM_START, ROM_END
from enum import Enum

ARCH_XML = """
<?xml version="1.0"?>
<!DOCTYPE feature SYSTEM "gdb-target.dtd">
<target version="1.0">
    <architecture>riscv:rv32</architecture>
    <feature name="org.gnu.gdb.riscv.cpu">
        <reg name="zero" bitsize="32" type="int"/>
        <reg name="ra" bitsize="32" type="code_ptr"/>
        <reg name="sp" bitsize="32" type="data_ptr"/>
        <reg name="gp" bitsize="32" type="data_ptr"/>
        <reg name="tp" bitsize="32" type="data_ptr"/>
        <reg name="t0" bitsize="32" type="int"/>
        <reg name="t1" bitsize="32" type="int"/>
        <reg name="t2" bitsize="32" type="int"/>
        <reg name="fp" bitsize="32" type="data_ptr"/>
        <reg name="s1" bitsize="32" type="int"/>
        <reg name="a0" bitsize="32" type="int"/>
        <reg name="a1" bitsize="32" type="int"/>
        <reg name="a2" bitsize="32" type="int"/>
        <reg name="a3" bitsize="32" type="int"/>
        <reg name="a4" bitsize="32" type="int"/>
        <reg name="a5" bitsize="32" type="int"/>
        <reg name="a6" bitsize="32" type="int"/>
        <reg name="a7" bitsize="32" type="int"/>
        <reg name="s2" bitsize="32" type="int"/>
        <reg name="s3" bitsize="32" type="int"/>
        <reg name="s4" bitsize="32" type="int"/>
        <reg name="s5" bitsize="32" type="int"/>
        <reg name="s6" bitsize="32" type="int"/>
        <reg name="s7" bitsize="32" type="int"/>
        <reg name="s8" bitsize="32" type="int"/>
        <reg name="s9" bitsize="32" type="int"/>
        <reg name="s10" bitsize="32" type="int"/>
        <reg name="s11" bitsize="32" type="int"/>
        <reg name="t3" bitsize="32" type="int"/>
        <reg name="t4" bitsize="32" type="int"/>
        <reg name="t5" bitsize="32" type="int"/>
        <reg name="t6" bitsize="32" type="int"/>
        <reg name="pc" bitsize="32" type="code_ptr"/>
    </feature>
</target>
"""

mhartid = 0xf14
mscratch = 0x340
medeleg = 0x302
mideleg = 0x303
mtvec = 0x305
mie = 0x304
mip = 0x344
mepc = 0x341
mstatus = 0x300
mcause = 0x342
mtval = 0x343
sscratch = 0x140
stvec = 0x105
sie = 0x104
sip = 0x144
sepc = 0x141
sstatus = 0x100
scause = 0x142
stval = 0x143
satp = 0x180
cycleh = 0xc80
timeh = 0xc80
instreth = 0xc82
mvendorid = 0xf11
marchid = 0xf12
mimpid = 0xf13
misa = 0x301
mcycleh = 0xc80
minstreth = 0xc82

csrs = [
    mhartid, mscratch, medeleg, mideleg, mtvec, mie, mip, mepc, mstatus, mcause, mtval, sscratch,
    stvec, sie, sip, sepc, sstatus, scause, stval, satp, cycleh, timeh, instreth, mvendorid, marchid,
    mimpid, misa, mcycleh, minstreth,
]

def swap_endianness32(v: str):
    return v[6:8] + v[4:6] + v[2:4] + v[0:2]

def in_bounds(value, start, end):
    return value >= start and value <= end

class GDBStub:
    class State(Enum):
        Stop        = 1
        NonStop     = 2
        ContinueTo  = 3

    def __init__(self, rv: RISCV):
        self.breakpoints = []
        self.state = self.State.Stop
        self.rv = rv
        self.continue_addr = 0

    def read_registers(self):
        regs = self.rv.state.regs + [self.rv.state.pc] #+ [self.rv.csr_read(csr) for csr in csrs]
        return "".join([swap_endianness32(f"{x:08x}") for x in regs])

    def write_registers(self, command: str):
        command = command[10:] # Chop off the "G XXXXXXXX" part, including the x0 reg
        for i in range(32):
            reg_value = int(command[:8], 16)
            command = command[8:]
            if i < 32:
                self.rv.state.regs[i+1] = reg_value
            else:
                self.rv.state.pc = reg_value

    def read_bytes_from_memory(self, command: str):
        command = command[1:] # Chop off the "m" part
        (addr, length) = command.split(",")
        addr = int(addr, 16)
        length = int(length, 16)

        if not (in_bounds(addr, RAM_START, RAM_END) or in_bounds(addr, ROM_START, ROM_END)):
            return ""

        # print(f"Attempting to read {length} bytes @ {addr:08x}")

        byte_str = ""
        for i in range(length):
            byte_str += f"{self.rv.memory_read8(addr +i):02x}"
        return byte_str

    def write_bytes_to_memory(self, command: str):
        command = command[1:] # Chop off the "M" part
        (addr, rest) = command.split(",")
        (length, data_bytes) = rest.split(":")
        addr = int(addr, 16)
        length = int(length)

        for i in range(length):
            byte = int(data_bytes[0:2], 16)
            self.rv.memory_write8(addr + i, byte)
            data_bytes = data_bytes[2:]

    def set_breakpoint(self, command: str):
        command = command[3:] # Chop off the "Z0," part
        addr = command.split(",")[0]
        addr = int(addr, 16)

        if addr not in self.breakpoints:
            self.breakpoints.append(addr)

    def remove_breakpoint(self, command: str):
        command = command[3:] # Chop off the "z0," part
        addr = command.split(",")[0]
        addr = int(addr, 16)

        if addr in self.breakpoints:
            self.breakpoints.remove(addr)

    def handle_vcont(self, command: str):
        command = command[6:] # Chop off the "vCont;" part
        if command.startswith("c"):
            self.state = self.State.NonStop
            return ""
        if command.startswith("s"):
            self.rv.fetch_decode_execute()
            self.state = self.State.Stop
            return "T05"
        else:
            print(f"Unsupported vCont command: {command}")


    def handle_query_packet(self, command: str):
        if command.startswith("qSupported"):
            print(command)
            return "PacketSize=4096;hwbreak+;swbreak-;vContSupported+;qXfer:features:read+"
        elif command.startswith("qfThreadInfo"):
            return "m1" # Single thread
        elif command.startswith("qAttached"):
            return "1"
        elif command.startswith("qC"):
            return "QC1"
        elif command.startswith("qC"):
            return "QC1"
        elif command.startswith("qXfer:features:read"):
            command = command[31:] # Remove "qXfer:features:read:target.xml:"
            (offset,length) = command.split(",")
            offset = int(offset, 16)
            length = int(length, 16)

            xml_part = ARCH_XML[offset:offset+length]

            return "l " + xml_part
            # return "l " if len(xml_part) < length else "m " + xml_part
        else:
            return ""

    def send_packet(self, conn: socket.socket, data: str):
        tx_packet = GDBPacket(data)
        conn.send(bytes(tx_packet.value, "ascii"))

    def start_server(self, port=3333, host="127.0.0.1"):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            s.listen()
            conn, addr = s.accept()
            s.setblocking(0)

            cycles = 0
            prev_pc = 0

            with conn:
                print(f"GDB connection accepted")

                # Buffers to store the raw data and the last received packet
                data = bytes([])
                rx_packet = GDBPacket()

                while True:
                    if self.state == self.State.Stop:
                        data = conn.recv(1)
                    elif self.state == self.State.NonStop or self.state == self.State.ContinueTo:
                        # Wait a maximum of 0.1ms before executing an instruction
                        # ready = select.select([conn], [], [], 0.0001)
                        # if ready[0]:
                        #     data = conn.recv(1)
                        # else:
                        # Run a cycle
                        # print(f"{cycles}: {self.rv.state.pc:08x}")
                        cycles += 1
                        self.rv.fetch_decode_execute()

                        if self.rv.gdb_breakpoint_hit:
                            self.send_packet(conn, "T05")
                            self.state = self.State.Stop
                            continue

                        if self.rv.state.pc == prev_pc:
                            print("Infinite loop detected")
                            self.send_packet(conn, "T05")
                            self.state = self.State.Stop
                            continue

                        prev_pc = self.rv.state.pc

                        if (self.state == self.State.ContinueTo and self.rv.state.pc == self.continue_addr) or self.rv.state.pc in self.breakpoints:
                            # We hit a breakpoint after a continue/step, send that info back to gdb
                            self.send_packet(conn, "T05")
                            self.state = self.State.Stop
                        continue
                    else:
                        pass

                    if not data:
                        print("Connection lost")
                        exit(1)

                    data = data.decode("utf-8")
                    (is_complete, data) = rx_packet.parse_rx_data(data)

                    # Check what kind of packet this is and take some action
                    if is_complete:
                        command = rx_packet.value
                        # print(f"> {rx_packet.value}")

                        if command.startswith("q"):
                            self.send_packet(conn, self.handle_query_packet(command))
                        elif command == "!":
                            self.send_packet(conn, "OK")
                        elif command.startswith("Hc"):
                            self.send_packet(conn, "OK")
                        elif command == "vCont?":
                            self.send_packet(conn, "vCont;c;s;C;S")
                        elif command.startswith("vCont;"):
                            self.send_packet(conn, self.handle_vcont(command))
                        elif command == "?":
                            self.send_packet(conn, "T05")
                        elif command == "g":
                            self.send_packet(conn, self.read_registers())
                        elif command.startswith("G "):
                            self.write_registers(command)
                            self.send_packet(conn, "OK")
                        elif command.startswith("m"):
                            self.send_packet(conn, self.read_bytes_from_memory(command))
                        elif command.startswith("M"):
                            self.write_bytes_to_memory(command)
                            self.send_packet(conn, "OK")
                        elif command.startswith("Z0"):
                            self.set_breakpoint(command)
                            self.send_packet(conn, "OK")
                        elif command.startswith("z0"):
                            self.remove_breakpoint(command)
                            self.send_packet(conn, "OK")
                        elif command.startswith("c"):
                            self.continue_execution(command)
                            self.send_packet(conn, "OK")
                        elif command.startswith("s"):
                            self.step_continue_execution(command)
                            self.send_packet(conn, "OK")
                        else:
                            print(f"[unknown command: {command}]")
                            # Anything else, we send back the empty response
                            self.send_packet(conn, "")

                        # Reset the packet so we can receive more data
                        rx_packet.reset()

class GDBPacketRxError(RuntimeError):
    pass

def compute_checksum(msg: str):
    return "{:02x}".format(sum(ord(c) for c in msg) & 0xff)

class GDBPacket:
    value: str
    is_rx: bool
    observed_sop: bool
    is_complete: bool
    checksum: str

    def __init__(self, packet_data=None):
        self.is_rx = packet_data is None

        self.checksum = "ff"
        self.observed_sop = False

        self.is_complete = not self.is_rx

        if self.is_rx:
            self.value = ""
        else:
            if packet_data == "":
                self.value = "+$#00"
            else:
                self.value = f"+${packet_data}#{compute_checksum(packet_data)}"

    # Return (complete, remaining_data)
    def parse_rx_data(self, data: str):
        if self.is_complete:
            raise GDBPacketRxError("Packet already complete")

        # Search for the start of the packet?
        if not self.observed_sop:
            while len(data) > 0 and data[0] != "$":
                data = data[1:]

            if len(data) > 0:
                self.observed_sop = True
                data = data[1:]

        # Search for the end of the packet and record the data
        while len(data) > 0:
            if data[0] == "#":
                self.is_complete = True
                data = data[1:]
                # This is a TCP stream, so just ignore the checksum data
                return (True, data)

            self.value += data[0]
            data = data[1:]

        return (False, "")

    def reset(self):
        self.__init__()
