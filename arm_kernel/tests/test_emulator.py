from arm_kernel.emulator import Emulator
from arm_kernel.memory import MemoryItem, MemoryType, ItemType
from arm_kernel.view import View
from arm_kernel.registers import select_registers

TEST_CODE_MOV = b"mov R0, #1"
TEST_CODE_ADD = b"add R0, #1"
TEST_CODE_LABEL = """
LDR R0, =test
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

def test_emulator_label_load():
    emu = Emulator()
    view = View()
    item = MemoryItem("test", ItemType.WORD, MemoryType.RO, 3, [1,2,3])
    emu.add_memory_item(item)
    state = emu.execute_code(TEST_CODE_LABEL)
    r0 = select_registers(state.registers, ['r0'])[0]
    want_address = emu.mem._mem_regions[MemoryType.RO].start
    assert r0.val == want_address

