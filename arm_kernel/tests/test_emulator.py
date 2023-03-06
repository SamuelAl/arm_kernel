

from arm_kernel.emulator import Emulator
from arm_kernel.memory import MemoryItem, MemoryType, ItemType
from arm_kernel.view import View
from arm_kernel.registers import select_registers

TEST_CODE_MOV = b"mov R0, #1"
TEST_CODE_ADD = b"add R0, #1"
TEST_CODE_LABEL = """
ldr r0, =test
ldr r1, [r0]
"""

TEST_SUBROUTINE_MAIN = """
mov r0, #0
bl subroutine
"""

TEST_SUBROUTINE_SUB = """
subroutine:
    mov R0, #1
    bx lr
"""

def test_emulator_label_load_ro():
    emu = Emulator()
    item = MemoryItem("test", ItemType.WORD, MemoryType.RO, 3, [1,2,3])
    emu.add_memory_item(item)
    
    emu.execute_code(TEST_CODE_LABEL)
    regs = emu.select_registers(['0-1'])
    r0 = regs[0]
    r1 = regs[1]
    want_address = emu.mem._mem_regions[MemoryType.RO].start
    assert r0.val == want_address
    assert r1.val == 1

def test_emulator_label_load_rw():
    emu = Emulator()
    item = MemoryItem("test", ItemType.WORD, MemoryType.RW, 3, [1,2,3])
    emu.add_memory_item(item)
    
    emu.execute_code(TEST_CODE_LABEL)
    regs = emu.select_registers(['0-1'])
    r0 = regs[0]
    r1 = regs[1]
    want_address = emu.mem._mem_regions[MemoryType.RW].start
    assert r0.val == want_address
    assert r1.val == 1


def test_subroutine_raw():
    emu = Emulator()
    asm_subroutine = emu.assemble(TEST_SUBROUTINE_SUB)
    # Assert no errors assembling
    assert asm_subroutine[2] is None
    asm_subroutine_code = asm_subroutine[0]
    subroutine_item = MemoryItem("subroutine", ItemType.RAW, MemoryType.SUBROUTINE, content=asm_subroutine_code)
    
    print(emu.mem.add_item(subroutine_item))
    emu._init_ldr(subroutine_item.label)

    emu.execute_code(TEST_SUBROUTINE_MAIN)
    reg0 = emu.select_registers(["0"])[0]
    assert reg0.val == 1

def test_subroutine_simple():
    emu = Emulator()
    emu.add_subroutine("subroutine", TEST_SUBROUTINE_SUB)
    emu.execute_code(TEST_SUBROUTINE_MAIN)
    reg0 = emu.select_registers(["0"])[0]
    assert reg0.val == 1
