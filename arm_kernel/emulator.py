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
    assembler = Ks(KS_ARCH_ARM, KS_MODE_ARM)
    emulator = Uc(UC_ARCH_ARM, UC_MODE_ARM)

    def __init__(self):
        # Set registers to 0
        for register in range(13):
             self.emulator.reg_write(UC_ARM_REG_R0 + register, 0x0)

        self.emulator.reg_write(UC_ARM_REG_APSR, 0xFFFFFFFF)
        self.emulator.mem_map(ADDRESS, 2 * 1024 * 1024)  


    def execute_code(self, code):
        try:

            # Initialize engine in X86-32bit mode.
            # ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
            encoding, count = self.assembler.asm(code)
            print("%s = %s (number of statements: %u)" % (code, encoding, count))
            assembled = bytes(encoding)
            print(assembled)
            
            # Initialize emulator in ARM mode
            # mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

            # map 2MB memory for this emulation

            # write machine code to be emulated to memory
            self.emulator.mem_write(ADDRESS, assembled)  

            # tracing all basic blocks with customized callback
            self.emulator.hook_add(UC_HOOK_BLOCK, hook_block)

            # tracing one instruction at ADDRESS with customized callback
            self.emulator.hook_add(UC_HOOK_CODE, hook_code, begin=ADDRESS, end=ADDRESS)

            # emulate machine code in infinite time
            self.emulator.emu_start(ADDRESS, ADDRESS + len(assembled))

            # now print out some registers
            print(">>> Emulation done. Below is the CPU context")

            return extract_cpu_state(self.emulator)

        except UcError as e:
            print("ERROR: %s" % e)