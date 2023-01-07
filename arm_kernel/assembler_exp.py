from __future__ import print_function
from keystone import *
from unicorn import *
from unicorn.arm_const import *
from capstone import *

ADDRESS    = 0x10000
MEMORY_ADDRESS = 0x20000

# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))

def sym_resolver(symbol, value):
    print("symbol: %s" % symbol)
    if symbol == b'testArray1':
        print("found")
        value[0] = MEMORY_ADDRESS
        return True
    
    return False



TEST_CODE1 = """
testArray1: \n
 .word 2, 2, 3 @ row 0\n
"""

TEST_CODE2 = """
LDR R0, =testArray1
LDR R1, [R0]
LDR R2, [R0, #8]
MOV R0, R1
"""

mem_asm = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
mem_asm.sym_resolver = sym_resolver
emulator = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
disassembler = Cs(CS_ARCH_ARM, CS_MODE_THUMB)


# Set registers to 0
for register in range(13):
        emulator.reg_write(UC_ARM_REG_R0 + register, 0x0)

encoded_memory, count_memory = mem_asm.asm(TEST_CODE1, MEMORY_ADDRESS)
encoded_code, count_code = mem_asm.asm(TEST_CODE2, ADDRESS)
print(encoded_code)
assembled_memory = bytes(encoded_memory)
assembled_code = bytes(encoded_code)

for i in disassembler.disasm(assembled_code, ADDRESS, count_code):
    print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))


emulator.reg_write(UC_ARM_REG_APSR, 0xFFFFFFFF)
emulator.mem_map(ADDRESS, 0x1000) 
emulator.mem_map(MEMORY_ADDRESS, 0x1000) 
emulator.mem_write(ADDRESS, assembled_code)  
emulator.mem_write(MEMORY_ADDRESS, assembled_memory)  
emulator.hook_add(UC_HOOK_CODE, hook_code, begin=ADDRESS, end=ADDRESS+len(assembled_code))
# Have to add ADDRESS | 1 to run in Thumb mode?
emulator.emu_start(ADDRESS | 1, ADDRESS + len(assembled_code))
print(emulator.reg_read(UC_ARM_REG_R1))
print(emulator.reg_read(UC_ARM_REG_R2))



