from fnmatch import fnmatch
from jinja2 import Environment, FileSystemLoader
from templates.register_view_temps import DETAILED_REGISTERS_TEMPLATE
from emulator import EmulatorState
import registers
import pynumparser
import re

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
    
    def gen_registers_view(self, view_config: dict, state: EmulatorState) -> str:
        template = self.env.from_string(DETAILED_REGISTERS_TEMPLATE)
        if "context" in view_config and view_config["context"] is not None:
            pattern = view_config["context"].split(",")
        else:
            pattern = ["0-12"]
        selected = self.select_registers(state.registers, pattern)
        registers = [(r.name, self._format(r.val, view_config["format"])) for r in selected]
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

    def _format(self, val: int, format: any) -> str:
        if format is None:
            return str(val)
        match format:
            case "hex":
                return hex(val)
            case _:
                return str(val)
