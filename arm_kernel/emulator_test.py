import emulator
from memory import MemoryItem, MemoryType, ItemType

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
    state = emu.execute_code(TEST_CODE_MOV)
    print(state)

    item = MemoryItem("test", ItemType.WORD, MemoryType.RO, 3, [1,2,3])
    emu.add_memory_item(item)
    state = emu.execute_code(TEST_CODE_LABEL)
    print(state)

if __name__ == "__main__":
    main()