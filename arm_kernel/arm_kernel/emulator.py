from __future__ import print_function
from collections import OrderedDict
from keystone import *
from unicorn import *
from unicorn.arm_const import *
from collections import namedtuple
import threading
from fnmatch import fnmatch
import re
import pynumparser

from arm_kernel.memory import Memory, MemoryItem
from arm_kernel import registers



# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))

# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))

def extract_cpu_state(uc):
    # Dictionary to hold registers.
    registers = OrderedDict()

    for register in range(13):
        registers["r%d" % register] = uc.reg_read(UC_ARM_REG_R0 + register)

    registers["r13"] = uc.reg_read(UC_ARM_REG_SP)
    registers["r14"] = uc.reg_read(UC_ARM_REG_LR)
    
    return {"registers": registers} 

EmulatorState = namedtuple("EmulatorState", ("registers", "memory"))
    
class Emulator:
    
    def __init__(self):

        # Initialize emulation suite.
        self.asm = Ks(KS_ARCH_ARM, KS_MODE_ARM)
        self.emu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
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
        self.emu.hook_add(UC_HOOK_CODE, hook_code, begin=self.mem.codepad_address)

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

    def execute_code(self, code):
        ret = []  # ret == [instrs, None] or [None, error]

        def parse_assembly():
            err = None
            try:
                instrs, count = self.asm.asm(code, as_bytes=True)
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
            self.emu.emu_start(self.mem.codepad_address, self.mem.codepad_address + len(assembled), timeout=5000000)

            return EmulatorState(self.registers, self.mem)

        except UcError as e:
            raise Exception("Error executing: %s" % e)
    
    def add_memory_item(self, item: MemoryItem):
        self.mem.add_item(item)