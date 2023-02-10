import re

from fnmatch import fnmatch
from jinja2 import Environment, FileSystemLoader
import pynumparser

from arm_kernel.templates.register import DETAILED_REGISTERS_TEMPLATE, NZCV_FLAGS_VIEW
from arm_kernel.templates.stack import STACK_VIEW
from arm_kernel.templates.memory import MEMORY_WORD_VIEW
from arm_kernel.emulator import EmulatorState
from arm_kernel import registers
from arm_kernel import memory

re_single_label = re.compile(r'^\w+$')

class View:
    '''
    View implements functionality to generate visualizations
    of the state of the CPU.
    '''

    def __init__(self):
        self.env = Environment()

    def get_view(self, view_config: dict, state: EmulatorState) -> str:
        '''Get HTML content representing a view of the CPU state'''

        match view_config["view"]:
            case "registers":
                return self.gen_registers_view(view_config, state)
            case "stack":
                return self.gen_stack_view(view_config, state)
            case "nzcv":
                return self.gen_nzcv_flags_view(state)
            case ("mem" | "memw" | "memh" | "memb") as mem_mode:
                return self.gen_mem_view(view_config, state, mem_mode)
    
    def gen_stack_view(self, view_config: dict, state: EmulatorState) -> str:
        template = self.env.from_string(STACK_VIEW)
        sp = self.select_registers(state.registers, ["sp"])[0]
        mem = state.memory
        sp_region = mem.stack_region
        rows = []
        for addrs in range(sp_region[1]-3, sp.val - 4, -4):
            print(hex(addrs))
            content = mem.read_address(addrs)
            content = int.from_bytes(content, "little")
            rows.append((self._format(addrs, "hex"), self._format(content, view_config.get("format"))))

        context = {
            "content": rows,
            "bottom_address": self._format(sp_region[1]+1, "hex"),
            "sp": self._format(sp.val, "hex")
        }
        return template.render(context)

    def gen_mem_view(self, view_config: dict, state: EmulatorState, mem_mode: str = "memw") -> str:
        template = self.env.from_string(MEMORY_WORD_VIEW)
        mem = state.memory

        metadata, content_bytes = self._get_memory_from_context(mem, view_config['context'])
        init_addrss = metadata[0]
        rows = []
        offset = 4
        match (mem_mode):
            case "memh":
                cols = 2
                col_offset = 2
            case "memb":
                cols = 4
                col_offset = 1
            case ("mem" | "memw"):
                cols = 1
                col_offset = 4

        for idx in range(0, len(content_bytes)-offset+1, offset):
            columns = []
            col_idx = idx
            for _ in range(cols):
                content = int.from_bytes(content_bytes[col_idx:col_idx + col_offset], "little")
                columns.append(self._format(content, view_config["format"], col_offset*2))
                col_idx += col_offset
            rows.append((self._format(init_addrss + idx, "hex"), columns))
        
        context = {
            "content": rows,
            "cols": cols
        }
        return template.render(context)
        # return f"""
        # <p>{str(content_bytes)}</p>
        # <p>{str(rows)}</p>
        # """

    def gen_nzcv_flags_view(self, state: EmulatorState) -> str:
        template = self.env.from_string(NZCV_FLAGS_VIEW)
        cpsr = self.select_registers(state.registers, ["cpsr"])[0]
        context = {
            "n": cpsr.N.fget().bin,
            "z": cpsr.Z.fget().bin,
            "c": cpsr.C.fget().bin,
            "v": cpsr.V.fget().bin
        }
        return template.render(context)

    def gen_registers_view(self, view_config: dict, state: EmulatorState) -> str:
        template = self.env.from_string(DETAILED_REGISTERS_TEMPLATE)
        if "context" in view_config and view_config["context"] is not None:
            pattern = view_config["context"].split(",")
        else:
            pattern = ["0-12"]
        selected = self.select_registers(state.registers, pattern)
        registers = [(r.name, self._format(r.val, view_config.get("format"))) for r in selected]
        context = {
            "registers": registers,
            "reg_count": len(selected)
        }
        print(context)
        return template.render(context)

    def select_registers(self, registers, patterns) -> list[registers.Register]:
        '''Filter the registers by name following the globs expressions.'''

        parser = pynumparser.NumberSequence()

        if not patterns:
            return list()

        selected = []
        for g in patterns:
            if re.match(r'[0-9]+(-[0-9]+)?', g):
                seq = parser.parse(g)
                for i in seq:
                    patterns.append("r%d" % i)
            elif g and g[0] == "!":
                selected = [r for r in selected if not fnmatch(r.name, g[1:])]
            else:
                more = [
                    r for r in registers if r not in selected and fnmatch(r.name, g)
                ]
                selected += more

        return selected

    def _format(self, val: int, format: any, size: int = 8) -> str:
        if format is None:
            return str(val)
        match format:
            case "hex":
                return self._padhexa(hex(val), size)
            case "bin":
                return bin(val)
            case _:
                return str(val)

    @staticmethod
    def _padhexa(s: str, size: int):
        return '0x' + s[2:].zfill(size)

    def _get_memory_from_context(self, mem: memory.Memory, context) -> tuple[tuple[int, int], bytearray]:
        if re_single_label.fullmatch(context) is None:
            raise Exception("Error: memory address pattern is not valid.")
        
        label = context
        addresses = mem.find_item(label)
        if addresses is None:
            raise Exception("Error: label was not found.")
        
        return (addresses, mem.read_item(label))