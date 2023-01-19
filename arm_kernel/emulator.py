from __future__ import print_function
from collections import OrderedDict
from unicorn import *
from unicorn.arm_const import *
from collections import namedtuple
from keystone import *
from memory import Memory, MemoryItem, MemoryType, ItemType
import registers
import threading
from fnmatch import fnmatch



# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))

# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))

def extract_cpu_state(uc):
    # Dictionary to hold registers.
    registers = OrderedDict()

    for register in range(13):
        registers["r%d" % register] = uc.reg_read(UC_ARM_REG_R0 + register)

    registers["r13"] = uc.reg_read(UC_ARM_REG_SP)
    registers["r14"] = uc.reg_read(UC_ARM_REG_LR)
    
    return {"registers": registers} 

class EmulatorState(
    namedtuple("registers", "memory")
):
    '''Represents the state of an emulated CPU'''

    def select_registers(regs, globs) -> list[registers.Register]:
        ''' Filter the registers by name following the globs expressions
            (fnmatch).

            Use '?' as a wildcard for a single character and '*' for zero or
            more characters:

            >>> list(select_registers(regs, ['e?x']))
            [eax = 0, ebx = 0]

            >>> list(select_registers(regs, ['e*']))
            [eax = 0, ebx = 0, eip = 0, esi = 0]

            >>> list(select_registers(regs, ['*i*']))
            [eip = 0, esi = 0]

            Charsets can be used with "[seq]" and "[!seq]".

            >>> list(select_registers(regs, ['e[acde]x']))
            [eax = 0]

            >>> list(select_registers(regs, ['e[!acde]x']))
            [ebx = 0]

            Exact names can be used as well:

            >>> list(select_registers(regs, ['eip']))
            [eip = 0]

            Several globs can be applied at the same time: any
            register matching at least one of the globs will be returned

            >>> list(select_registers(regs, ["eax", "ebx"]))
            [eax = 0, ebx = 0]

            A glob prefixed with "!" will negate the match. This is a way
            to block registers matched by a previous glob:

            >>> list(select_registers(regs, ["e*", "!eip"]))
            [eax = 0, ebx = 0, esi = 0]

            The registers allowed by globs determine also the order: registers
            allowed first appear before.

            >>> list(select_registers(regs, ["e*", "!e?x", "eax"]))
            [eip = 0, esi = 0, eax = 0]

            If not glob is given no register is selected:

            >>> list(select_registers(regs, []))
            []
        '''

        if not globs:
            return iter(list())

        selected = []
        for g in globs:
            if g and g[0] == "!":
                selected = [r for r in selected if not fnmatch(r.name, g[1:])]
            else:
                more = [
                    r for r in regs if r not in selected and fnmatch(r.name, g)
                ]
                selected += more

        return selected


    


class Emulator:
    
    def __init__(self):

        # Initialize emulation suite.
        self.asm = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
        self.emu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self.mem = Memory(self.emu)

        # Setup symbol resolution using managed memory.
        def sym_resolver(symbol, value):
            print("symbol: %s" % symbol.decode('utf-8'))
            address, _ = self.mem.find_item(symbol.decode('utf-8'))
            if address is not None:
                print("found")
                value[0] = address
                return True
            
            return False 

        self.asm.sym_resolver = sym_resolver

        # Setup hooks:
        # tracing one instruction with customized callback
        self.emu.hook_add(UC_HOOK_CODE, hook_code, begin=self.mem.codepad_address)

        # Set registers to 0
        for register in range(13):
             self.emu.reg_write(UC_ARM_REG_R0 + register, 0x0)

        self.emu.reg_write(UC_ARM_REG_APSR, 0xFFFFFFFF)

        # Test item
        item = MemoryItem("test", ItemType.WORD, MemoryType.RO, 3, [1,2,3])
        self.mem.add_item(item) 


    def execute_code(self, code):
        ret = []  # ret == [instrs, None] or [None, error]

        def parse_assembly():
            err = None
            try:
                instrs, count = self.asm.asm(code, as_bytes=True)
                ret.extend((instrs, count, None))
            except Exception as e:
                instrs, count, err = None, None, e
                ret.extend((instrs, count, err))
            

        th = threading.Thread(target=parse_assembly, daemon=True)
        th.start()
        th.join(5)

        # keystone hang?
        if not ret or th.is_alive():
            raise TimeoutError("Assembler hanged due to syntax error or bug.")

        assembled, count, err = ret

        # keystone failed?
        if err is not None:
            raise err

        # valid assembly but not instructions there (like a comment)
        if not assembled:
            return extract_cpu_state(self.emu)

        try:
            # write machine code to be emulated to memory
            self.mem.write_code(assembled)  

            # emulate machine code
            self.emu.emu_start(self.mem.codepad_address | 1, self.mem.codepad_address + len(assembled), count=count)

            return extract_cpu_state(self.emu)

        except UcError as e:
            print("ERROR: %s" % e)
    
    def add_memory_item(self, item: MemoryItem):
        self.mem.add_item(item)