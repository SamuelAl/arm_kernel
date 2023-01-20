import emulator
from memory import MemoryItem, MemoryType, ItemType
from view import View

TEST_CODE_MOV = b"mov R0, #1"
TEST_CODE_ADD = b"add R0, #1"
TEST_CODE_LABEL = """
LDR R0, =test
LDR R1, [R0]
LDR R2, [R0, #8]
MOV R0, R1
"""
TEST_CODE_STACK = """
MOV R0, #1
MOV R1, #2
MOV R2, #3
MOV R3, #4
PUSH {R0-R3}
"""

def main():
    emu = emulator.Emulator()
    view = View()
    state = emu.execute_code(TEST_CODE_STACK)
    # print(state)
    cpsr = emu.select_registers(["cpsr"])[0]
    print(cpsr.N.fget().bin)
    
    gen_view = view.gen_nzcv_flags_view(state)
    print(gen_view)

if __name__ == "__main__":
    main()