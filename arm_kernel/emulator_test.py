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

def main():
    emu = emulator.Emulator()
    view = View()
    state = emu.execute_code(TEST_CODE_MOV)
    print(state)
    gen_view = view.gen_registers_view({"contex": "1-5"},state)
    print(gen_view)

if __name__ == "__main__":
    main()