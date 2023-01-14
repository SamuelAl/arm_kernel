from fnmatch import fnmatch
from jinja2 import Environment, FileSystemLoader
from templates.register_view_temps import DETAILED_REGISTERS_TEMPLATE

class View:
    '''
    View implements functionality to generate visualizations
    of the state of the CPU.
    '''

    def __init__(self):
        self.env = Environment()

    def get_view(self, view_config: dict, state: dict) -> str:
        '''Get HTML content representing a view of the CPU state'''

        match view_config["view"]:
            case "registers":
                return self.gen_registers_view(view_config, state)
    
    def gen_registers_view(self, view_config: dict, state: dict) -> str:
        template = self.env.from_string(DETAILED_REGISTERS_TEMPLATE)
        index_pattern = view_config["context"]
        globs = [f"r[{index_pattern}]"]
        selected = []
        for g in globs:
            if g and g[0] == "!":
                selected = [r for r in selected if not fnmatch(r.name, g[1:])]
            else:
                more = [
                    (key, value) for key, value in state["registers"].items() if (key, value) not in selected and fnmatch(key, g)
                ]
                selected += more

        context = {
            "registers": selected,
            "reg_count": len(selected)
        }
        print(context)
        return template.render(context)

test_state = {
    "registers": {
        "r0": 0,
        "r1": 1,
        "r2": 2,
        "r3": 3,
    }
}

view_config = {
    "view": "registers",
    "context": "1-3,0"
}

view = View()
print(view.get_view(view_config, test_state))