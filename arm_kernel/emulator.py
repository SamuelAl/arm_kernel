from __future__ import print_function
from unicorn import *
from unicorn.arm_const import *
from keystone import *
from memory import Memory, MemoryItem, MemoryType, ItemType


# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))

# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))

def extract_cpu_state(uc):
    # Dictionary to hold registers.
    state = {}

    for register in range(13):
        state["R%d" % register] = uc.reg_read(UC_ARM_REG_R0 + register)
    
    return state 


class Emulator:
    
    def __init__(self):

        # Initialize emulation suite.
        self.asm = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
        self.emu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self.mem = Memory(self.emu)

        # Setup symbol resolution using managed memory.
        def sym_resolver(symbol, value):
            print("symbol: %s" % symbol.decode('utf-8'))
            address, _ = self.mem.find_item(symbol.decode('utf-8'))
            if address is not None:
                print("found")
                value[0] = address
                return True
            
            return False 

        self.asm.sym_resolver = sym_resolver

        # Setup hooks:
        # tracing one instruction with customized callback
        self.emu.hook_add(UC_HOOK_CODE, hook_code, begin=self.mem.codepad_address)

        # Set registers to 0
        for register in range(13):
             self.emu.reg_write(UC_ARM_REG_R0 + register, 0x0)

        self.emu.reg_write(UC_ARM_REG_APSR, 0xFFFFFFFF)

        # Test item
        item = MemoryItem("test", ItemType.WORD, MemoryType.RO, 3, [1,2,3])
        self.mem.add_item(item) 


    def execute_code(self, code):

        try:
            # Initialize engine in X86-32bit mode.
            assembled, count = self.asm.asm(code, as_bytes=True)
            print(assembled)

            # write machine code to be emulated to memory
            self.mem.write_code(assembled)  

            # emulate machine code in infinite time
            self.emu.emu_start(self.mem.codepad_address | 1, self.mem.codepad_address + len(assembled), count=count)

            return extract_cpu_state(self.emu)

        except UcError as e:
            print("ERROR: %s" % e)
    
    def add_memory_item(self, item: MemoryItem):
        self.mem.add_item(item)