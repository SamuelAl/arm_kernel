from __future__ import print_function
from collections import OrderedDict
from keystone import *
from unicorn import *
from unicorn.arm_const import *
from capstone import *
from collections import namedtuple
import threading
from fnmatch import fnmatch
import re
import pynumparser

from arm_kernel.memory import ItemType, Memory, MemoryItem, MemoryType
from arm_kernel import registers

# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))

# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))


EmulatorState = namedtuple("EmulatorState", ("registers", "memory"))
    
class Emulator:
    
    def __init__(self):

        # Initialize emulation suite.
        self.asm = Ks(KS_ARCH_ARM, KS_MODE_ARM)
        self.emu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        self.mem = Memory(self.emu)

        # Setup symbol resolution using managed memory.
        def sym_resolver(symbol, value):
            print("symbol: %s" % symbol.decode('utf-8'))
            address, _ = self.mem.find_item(symbol.decode('utf-8'))
            if address is not None:
                value[0] = address
                return True
            
            return False 

        self.asm.sym_resolver = sym_resolver

        # Setup hooks:
        # tracing one instruction with customized callback
        # self.emu.hook_add(UC_HOOK_CODE, hook_code, begin=self.mem.codepad_address)

        # Setup registers.
        self.registers = registers.get_registers(self.emu)
        
        # Set registers to 0
        for register in self.select_registers(['0-12']):
            register.val = 0

        self.emu.reg_write(UC_ARM_REG_APSR, 0xFFFFFFFF)


    def select_registers(self, patterns) -> list[registers.Register]:
        '''Filter the registers by name following the globs expressions.'''

        parser = pynumparser.NumberSequence()

        if not patterns:
            return list()

        selected = []
        for g in patterns:
            if re.match(r'[0-9]+(-[0-9]+)?', g):
                seq = parser.parse(g)
                for i in seq:
                    patterns.append("r%d" % i)
            elif g and g[0] == "!":
                selected = [r for r in selected if not fnmatch(r.name, g[1:])]
            else:
                more = [
                    r for r in self.registers if r not in selected and fnmatch(r.name, g)
                ]
                selected += more

        return selected

    def assemble(self, code:str, addrs:int = 0) -> tuple[bytes | list, int, Exception | None]:
        try:
            instrs, count = self.asm.asm(code, addrs, as_bytes=True)
            return (instrs, count, None)
        except Exception as e:
            instrs, count, err = None, None, e
            return (instrs, count, err)
        
    def disassemble(self, code: bytearray | bytes | list, addrs: int = 0, count: int = 0) -> str:
        res = ""
        for i in self.cs.disasm(code, offset=addrs, count=count):
            res += "0x%x:\t%s\t%s\t%s\n" % (i.address, i.bytes.hex(), i.mnemonic, i.op_str)
        return res

    def execute_code(self, code):
        ret = []  # ret == [instrs, None] or [None, error]

        def parse_assembly():
            err = None
            try:
                instrs, count = self.asm.asm(code, addr=self.mem.codepad_address, as_bytes=True)
                ret.extend((instrs, count, None))
            except Exception as e:
                instrs, count, err = None, None, e
                ret.extend((instrs, count, err))
            

        th = threading.Thread(target=parse_assembly, daemon=True)
        th.start()
        th.join(5)

        # keystone hang?
        if not ret or th.is_alive():
            raise TimeoutError("Assembler hanged due to syntax error or bug.")

        assembled, count, err = ret

        # keystone failed?
        if err is not None:
            raise err

        # valid assembly but not instructions there (like a comment)
        if not assembled:
            return EmulatorState(self.registers, self.mem)

        try:
            # write machine code to be emulated to memory
            self.mem.write_code(assembled)  

            # emulate machine code
            until = self.mem.codepad_address + len(assembled)
            self.emu.ctl_remove_cache(self.mem.codepad_address, until+1)
            self.emu.emu_start(self.mem.codepad_address, until, timeout=5000000)

            return EmulatorState(self.registers, self.mem)

        except UcError as e:
            raise Exception("Error executing: %s" % e)
    
    def add_memory_item(self, item: MemoryItem):
        self.mem.add_item(item)
        try:
            self._init_ldr(item.label)
        except:
            pass

    def add_subroutine(self, label, subroutine):
        """Assembles and adds a subroutine to the subroutine memory region."""
        subroutine_addrs = self.mem.subroutine_region.start
        encoded, count, err = self.assemble(subroutine, subroutine_addrs)
        if err is not None:
            raise Exception(f"Error assembling subroutine: {err}")
        item = MemoryItem(label, ItemType.RAW, MemoryType.SUBROUTINE, content=encoded)
        return self.add_memory_item(item)

    def _init_ldr(self, label: str):
        """This resolves first LDR unicorn bug."""
        # Memorize current r0 value to restore later.
        r0_val = self.emu.reg_read(UC_ARM_REG_R0)
        # Execute dummy LDR code.
        code = f"""LDR R0, ={label}"""
        self.execute_code(code)
        # Restore original r0 value.
        self.emu.reg_write(UC_ARM_REG_R0, r0_val)