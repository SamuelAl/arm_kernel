from unicorn import Uc
from unicorn.arm_const import *

from arm_kernel.memory import *

def test_add_string():
    emu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    mem = Memory(emu)
    
    # Create item
    item = MemoryItem("test", ItemType.STRING, MemoryType.RO, content="test")
    assert item.byte_size == len("test") + 1

    # Add to memory
    mem.add_item(item)
    res = mem.find_item("test")
    assert res[1] == item.byte_size

