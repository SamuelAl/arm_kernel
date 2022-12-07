from __future__ import print_function
from unicorn import *
from unicorn.arm_const import *
from keystone import *

# memory address where emulation starts
ADDRESS    = 0x10000

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
    asm = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
    emu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

    def __init__(self):
        # Set registers to 0
        for register in range(13):
             self.emu.reg_write(UC_ARM_REG_R0 + register, 0x0)

        self.emu.reg_write(UC_ARM_REG_APSR, 0xFFFFFFFF)
        self.emu.mem_map(ADDRESS, 2 * 1024 * 1024)  


    def execute_code(self, code):
        try:

            # Initialize engine in X86-32bit mode.
            encoding, count = self.asm.asm(code)
            print("%s = %s (number of statements: %u)" % (code, encoding, count))
            assembled = bytes(encoding)
            print(assembled)

            # write machine code to be emulated to memory
            self.emu.mem_write(ADDRESS, assembled)  

            # tracing all basic blocks with customized callback
            self.emu.hook_add(UC_HOOK_BLOCK, hook_block)

            # tracing one instruction at ADDRESS with customized callback
            self.emu.hook_add(UC_HOOK_CODE, hook_code, begin=ADDRESS, end=ADDRESS)

            # emulate machine code in infinite time
            self.emu.emu_start(ADDRESS | 1, ADDRESS + len(assembled))

            # now print out some registers
            print(">>> Emulation done. Below is the CPU context")

            return extract_cpu_state(self.emu)

        except UcError as e:
            print("ERROR: %s" % e)