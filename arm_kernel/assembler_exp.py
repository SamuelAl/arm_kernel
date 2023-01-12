from __future__ import print_function
from keystone import *
from unicorn import *
from unicorn.arm_const import *
from capstone import *
from memory import Memory, MemoryItem, MemoryType, ItemType

mem_asm = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
emulator = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
disassembler = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
mem = Memory(emulator)

# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))

def sym_resolver(symbol, value):
    print("symbol: %s" % symbol.decode('utf-8'))

    address, _ = mem.find_item(symbol.decode('utf-8'))
    if address is not None:
        print("found")
        value[0] = address
        return True
    
    return False

mem_asm.sym_resolver = sym_resolver

item = MemoryItem("testArray1", ItemType.WORD, MemoryType.RO, 3, [1,2,3])
mem.add_item(item)

TEST_CODE2 = """
LDR R0, =testArray1
LDR R1, [R0]
LDR R2, [R0, #8]
MOV R0, R1
"""

# Set registers to 0
for register in range(13):
        emulator.reg_write(UC_ARM_REG_R0 + register, 0x0)

assembled_code, count_code = mem_asm.asm(TEST_CODE2, mem.codepad_address, as_bytes=True)
print(assembled_code)
print(f"count_code: {count_code}, len: {len(assembled_code)}")
for i in disassembler.disasm(assembled_code, mem.codepad_address, count_code):
    print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))


emulator.reg_write(UC_ARM_REG_APSR, 0xFFFFFFFF)
mem.write_code(assembled_code)  
emulator.hook_add(UC_HOOK_CODE, hook_code, begin=mem.codepad_address, end=mem.codepad_address+len(assembled_code))
# Have to add ADDRESS | 1 to run in Thumb mode
emulator.emu_start(mem.codepad_address | 1, mem.codepad_address + len(assembled_code), count=count_code)
print(emulator.reg_read(UC_ARM_REG_R0))
print(emulator.reg_read(UC_ARM_REG_R2))