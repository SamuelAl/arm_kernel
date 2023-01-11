# Memory manages the virtual memory of the kernel emulator.
# 
# There are three main regions of memory:
# - Scratch pad: Where the codeblocks are executed: 500KB
# - Subroutines: Readonly block to store custom subroutines: 1MB
# - Main Memory: Pages of memory according to config.

# Sources:
# - Memory class from bad-address/iasm

from collections import namedtuple
from enum import Enum
from sortedcontainers import SortedList
from unicorn import *
from unicorn.arm_const import *

ALIGNMENT = 4 * 1024

def next_aligned(n: int, alignment: int = ALIGNMENT) -> int:
    return (n + alignment) & -(alignment-1)

STACK_ADDR = 0x0
STACK_SZ = 1024*1024

# Default profile
DEFAULT_BASE = 0x400000
DEFAULT_CODEPAD_MEM_START = DEFAULT_BASE
DEFAULT_CODEPAD_MEM_SZ = 500 * (1 << 10) #500kb
DEFAULT_SUBROUTINE_MEM_START = next_aligned(DEFAULT_CODEPAD_MEM_START + DEFAULT_CODEPAD_MEM_SZ)
DEFAULT_SUBROUTINE_MEM_SZ = 1 << 20 #1Mb
DEFAULT_MAIN_MEM_START = next_aligned(DEFAULT_SUBROUTINE_MEM_START + DEFAULT_SUBROUTINE_MEM_SZ)
DEFAULT_MAIN_MEM_SZ = 4 * (1 << 20) #4Mb
DEFAULT_PAGE_SZ = 1 << 10 #1Kb

DEFAULT_RW_MEM_START = DEFAULT_MAIN_MEM_START
DEFAULT_RW_MEM_SZ = DEFAULT_PAGE_SZ
DEFAULT_RO_MEM_START =  next_aligned(DEFAULT_RW_MEM_START + DEFAULT_RW_MEM_SZ)
DEFAULT_RO_MEM_SZ = DEFAULT_PAGE_SZ

class MemoryType(Enum):
    CODE = 1
    MAIN = 2
    RO = 3
    RW = 4
    SUBROUTINE = 5 
    STACK = 6

class ItemType(Enum):
    BYTE = 1
    HWORD = 2
    WORD = 4
    INT = 10
    STRING = 20
    SPACE = 0

ITEM_BYTE_SZ = {
    ItemType.BYTE: 1,
    ItemType.HWORD: 2,
    ItemType.WORD: 4,
    ItemType.INT: 4,
    ItemType.STRING: 1,
    ItemType.SPACE: 1
}

# Item: Tuple("label", type, access, size, content)
class MemoryItem:

    def __init__(self, label: str, type: ItemType, access: MemoryType, size: int = 1, content = None):
        self.label = label
        self.type = type
        self.access = access
        self.content = content
        self.size = size
        self.byte_size = self.calculate_bytes_count()

    def _type_bytes(self, type: ItemType) -> int:
        return ITEM_BYTE_SZ[type]

    def calculate_bytes_count(self):
        byte_count = self._type_bytes(self.type)

        # Handle strings
        if type is ItemType.STRING:
            if isinstance(self.content, list):
                raise Exception("Only strings must be single, not lists.")
            return len(self.content)
            
        # Handle SPACE
        elif type is ItemType.SPACE:
            return self.size * self.byte_count

        # Handle other types
        if isinstance(self.content, list):
            return max(self.size * byte_count, len(self.content) * byte_count)
        else:
            return byte_count

    # ref: [https://www.geeksforgeeks.org/how-to-convert-int-to-bytes-in-python/]    
    def to_bytes(self):
        
        # Handle everything but strings and SPACE for now
        bytes_per_val = self._type_bytes(self.type)

        # Handle space
        if self.type is ItemType.SPACE:
            return bytes([0] * bytes_per_val * self.size)

        # Handle list
        if isinstance(self.content, list):
            byte_ls = []
            for val in self.content:
                words = val.to_bytes(bytes_per_val, 'little')
                for byte in words:
                    byte_ls.append(byte)
            return bytes(byte_ls)
        else:
            return self.content.to_bytes(bytes_per_val, 'little')

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
        Memory Page @ 0x{self.start:x}:
        Type: {self.type},
        Capacity: {self.capacity} B,
        Size: {self.size},
        Next Addrs: 0x{self.next_address:x},
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
        
        #TODO: Create new page if no page found
        raise Exception("No page found") # this will be substituted by the creation of a new page

    def add_item(self, item: MemoryItem):
        #TODO: Validate item.

        # get page with space
        page = self._find_page(item.access, item.byte_size)

        # Add content to memory
        # get bytes
        print(item.to_bytes())
        self._mu.mem_write(page.next_address, item.to_bytes())


    
        

mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB) 
mem = Memory(mu=mu)

item = MemoryItem("label",  ItemType.SPACE, MemoryType.RO, size=8, content=[1,2])
page = mem.add_item(item)
