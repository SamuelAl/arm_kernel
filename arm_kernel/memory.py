# Memory manages the virtual memory of the kernel emulator.
# 
# There are three main regions of memory:
# - Scratch pad: Where the codeblocks are executed: 500KB
# - Subroutines: Readonly block to store custom subroutines: 1MB
# - Main Memory: Pages of memory according to config.

# Sources:
# - Memory class from bad-address/iasm

from enum import Enum
from sortedcontainers import SortedList
from unicorn import *
from unicorn.arm_const import *

ALIGNMENT = 4 * 1024

def next_aligned(n: int, alignment: int = ALIGNMENT) -> int:
    return (n + alignment) & -(alignment-1)

class MemoryType(Enum):
    CODE = 1
    MAIN = 2
    RO = 3
    RW = 4
    SUBROUTINE = 5 
    STACK = 6

# Item: Tuple("label", type, access, size, content)

class ItemType(Enum):
    BYTE = 1
    HWORD = 2
    WORD = 4
    INT = 10
    STRING = 20
    SPACE = 0

STACK_ADDR = 0x0
STACK_SZ = 1024*1024

# Default profile
DEFAULT_BASE = 0x400000
DEFAULT_CODEPAD_MEM_START = DEFAULT_BASE
DEFAULT_CODEPAD_MEM_SZ = 500 * (2 << 10) #500kb
DEFAULT_SUBROUTINE_MEM_START = next_aligned(DEFAULT_CODEPAD_MEM_START + DEFAULT_CODEPAD_MEM_SZ)
DEFAULT_SUBROUTINE_MEM_SZ = 2 << 20 #1Mb
DEFAULT_MAIN_MEM_START = next_aligned(DEFAULT_SUBROUTINE_MEM_START + DEFAULT_SUBROUTINE_MEM_SZ)
DEFAULT_MAIN_MEM_SZ = 4 * (2 << 20) #4Mb
DEFAULT_PAGE_SZ = 2 << 10 #1Kb

DEFAULT_RW_MEM_START = DEFAULT_MAIN_MEM_START
DEFAULT_RW_MEM_SZ = DEFAULT_PAGE_SZ
DEFAULT_RO_MEM_START =  next_aligned(DEFAULT_RW_MEM_START + DEFAULT_RW_MEM_SZ)
DEFAULT_RO_MEM_SZ = DEFAULT_PAGE_SZ

class MemoryPage:

    def __init__(self, type: MemoryType, start: int, capacity: int):
        self.type = type
        self.start = start
        self.capacity = capacity
        self.size = 0
        self.next_address = start
        self.labels = []

    def __repr__(self) -> str:
        return f"""
        Memory Page @ {self.start}:
        Type: {self.type},
        Capacity: {self.capacity},
        Size: {self.size},
        Next Addrs: {self.next_address},
        Labels: {len(self.labels)}
        """

class Memory:
    def __init__(self, mu: unicorn.Uc):
        self._mu = mu

        # Setup main memory regions map
        self._mem_regions = {
            MemoryType.CODE: (DEFAULT_CODEPAD_MEM_START, DEFAULT_CODEPAD_MEM_START + DEFAULT_CODEPAD_MEM_SZ), 
            MemoryType.SUBROUTINE: (DEFAULT_SUBROUTINE_MEM_START, DEFAULT_SUBROUTINE_MEM_START + DEFAULT_SUBROUTINE_MEM_SZ),
            MemoryType.MAIN: (DEFAULT_MAIN_MEM_START, DEFAULT_MAIN_MEM_START +  DEFAULT_MAIN_MEM_SZ)
        }

        self._mu.mem_map(address=DEFAULT_CODEPAD_MEM_START, size=DEFAULT_CODEPAD_MEM_SZ, perms=UC_PROT_EXEC | UC_PROT_READ)
        self._mu.mem_map(address=DEFAULT_SUBROUTINE_MEM_START, size=DEFAULT_SUBROUTINE_MEM_SZ, perms=UC_PROT_EXEC | UC_PROT_READ)

        # Setup pages map
        self._rw_pages = SortedList(iterable=[
            MemoryPage(MemoryType.RW, DEFAULT_RW_MEM_START, DEFAULT_RW_MEM_SZ)
        ], key=lambda x: x.start)

        self._ro_pages = SortedList(iterable=[
            MemoryPage(MemoryType.RO, DEFAULT_RO_MEM_START, DEFAULT_RO_MEM_SZ)
        ], key=lambda x: x.start)

        self._mu.mem_map(DEFAULT_RW_MEM_START, DEFAULT_RW_MEM_SZ)
        self._mu.mem_map(DEFAULT_RO_MEM_START, DEFAULT_RO_MEM_SZ, perms=UC_PROT_READ)

        self._items = {}

    def _find_page(self, access: MemoryType, size: int) -> MemoryPage:
        # Find memory list
        list = SortedList()
        if access is MemoryType.RO:
           list = self._ro_pages
        else:
            list = self._rw_pages
        
        for page in list:
            if page.capacity - page.size >= size:
                return page

    def add_item(self, item):
        #TODO: Validate item.

        # get page with space
        pass
        

mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB) 
mem = Memory(mu=mu)

print(mem._ro_pages)
page = mem._find_page(MemoryType.RO, 100)
print(page)
