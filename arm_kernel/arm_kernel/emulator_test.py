from . import emulator
from .memory import MemoryItem, MemoryType, ItemType
from .view import View

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

TEST_CONFIG = """__config__
memory:
    items:
        label1:
            type: word
            access: ro
            content: [1,2,3]
"""

def main():
    emu = emulator.Emulator()
    view = View()
    item = MemoryItem("label1", ItemType.WORD, MemoryType.RW, 3, [1,2,3])
    emu.mem.add_item(item)
    data = view._get_memory_from_context(emu.mem, "label1")
    print(data)

if __name__ == "__main__":
    main()