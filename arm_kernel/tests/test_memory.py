from unicorn import Uc
from unicorn.arm_const import *

from arm_kernel.memory import *

DEFAULT_REGION_START = 0x1000
DEFAULT_REGION_END = 0x7000

# def test_add_string():
#     emu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
#     mem = Memory(emu)
    
#     # Create item
#     item = MemoryItem("test", ItemType.STRING, MemoryType.RO, content="test")
#     assert item.byte_size == len("test") + 1

#     # Add to memory
#     mem.add_item(item)
#     res = mem.find_item("test")
#     assert res[1] == item.byte_size

def test_memory_region_constructor():
    emu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

    START = 0x4000
    END = 0X5000
    region = MemoryRegion(emu, START, END)
    assert region.start == START
    assert region.end == END

def test_memory_region_add_page():
    region = create_test_region()

    PAGE_TYPE = MemoryType.CODE
    PAGE_SIZE = 1 << 10
    
    # Add 2 pages
    want_start = DEFAULT_REGION_START
    for i in range(2):
        page = region.add_page(PAGE_SIZE, PAGE_TYPE)
        assert page.capacity == PAGE_SIZE
        assert page.start == want_start
        assert page.type == PAGE_TYPE
        want_start = next_aligned(want_start + PAGE_SIZE)

def test_memory_region_find_free_page():
    # Setup
    region = create_test_region()
    PAGE_TYPE = MemoryType.RW
    PAGE_SIZE = 4 * KB_SIZE

    # Create an initial page
    page_1 = region.add_page(PAGE_SIZE, PAGE_TYPE)

    # Look for free page
    got_page = region.find_free_page(PAGE_TYPE, PAGE_SIZE, False)
    assert got_page is page_1

    # Create a new page
    got_page = region.find_free_page(PAGE_TYPE, PAGE_SIZE + 1, True)
    assert got_page is not page_1
    assert got_page.capacity == PAGE_SIZE * 2 # next multiple of KB_SIZE
    page_2 = got_page

    # Look for free page with multiple pages
    got_page = region.find_free_page(PAGE_TYPE, PAGE_SIZE, False)
    assert got_page is page_1
    got_page = region.find_free_page(PAGE_TYPE, PAGE_SIZE + 1, False)
    assert got_page is page_2

    # Modify page 1
    item = MemoryItem("test", ItemType.BYTE, PAGE_TYPE, 4, [1,2,3,4])
    region.add_item(item)
    item_start = region._items["test"][0]
    assert item_start is page_1.start
    got_page = region.find_free_page(PAGE_TYPE, PAGE_SIZE, False)
    assert got_page is page_2

def test_memory_region_add_item():
    region = create_test_region()
    item = MemoryItem("test", ItemType.BYTE, MemoryType.RO, 4, [1,2,3,4])
    res = region.add_item(item)
    assert res[0] == DEFAULT_REGION_START # check item aligned with start of region

def test_memory_region_find_item():
    region = create_test_region()
    item = MemoryItem("test", ItemType.BYTE, MemoryType.RO, 4, [1,2,3,4])
    item_addrs = region.add_item(item)[0]
    got_addrs = region.find_item(item.label)[0]
    assert got_addrs == item_addrs



def create_test_region(start: int = DEFAULT_REGION_START, end: int = DEFAULT_REGION_END) -> MemoryRegion:
    emu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    return MemoryRegion(emu, start, end)






