from __future__ import print_function
from sys import implementation
from ipykernel.kernelbase import Kernel
from emulator import Emulator
from preprocessor import Preprocessor, BlockType
from jinja2 import Environment, FileSystemLoader
from templates.register_view_temps import DETAILED_REGISTERS_TEMPLATE

class ArmKernel(Kernel):
    implementation = 'ARM Assembly'
    implementation_version = '1.0'
    language = 'ARM Assembly'
    language_version = '0.1'
    language_info = {
        'name': 'Any text',
        'mimetype': 'text/html',
        'file_extension': '.txt',
    }
    banner = "ARM Assembly - code an ARM CPU"

    emulator = Emulator()
    environment = Environment(loader=FileSystemLoader("templates/"))

    def _state_to_reg_view(self, state: dict) -> str:
        template = self.environment.from_string(DETAILED_REGISTERS_TEMPLATE)
        registers = []
        for key, value in state.items():
            registers.append((key, hex(value)))

        context = {
            "registers": registers,
            "reg_count": len(registers)
        }
        return template.render(context)


    def _execute_code(self, code: str):
        state = self.emulator.execute_code(code)
        stream_content = {
            'metadata': {},
            'data': {'text/html': self._state_to_reg_view(state)}
            }
        self.send_response(self.iopub_socket, 'display_data', stream_content)


    def _handle_config(self, config: dict):
        # For now only handle memory:
        labels = "labels: "
        if config.get("memory") is not None:
            mem_config = config["memory"]
            for item in mem_config.get("items"):
                self.emulator.add_memory_item(item)
                labels = labels + item.label + " "

        stream_content = {
            'metadata': {},
            'data': {'text/html': f"<p>-- kernel configured successfully --</p>"}
            }
        self.send_response(self.iopub_socket, 'display_data', stream_content)
        

    def do_execute(self, code, silent, store_history=True, user_expressions=None, allow_stdin=False):
        if not silent:

            # Preprocess
            parsed_block = Preprocessor.parse(code)
            print(parsed_block)
            match parsed_block[0]:
                case BlockType.TEXT:
                    self._execute_code(parsed_block[1])
                case BlockType.CONFIG:
                    self._handle_config(parsed_block[1])


            return {'status': 'ok',
                    # The base class increments the execution count
                    'execution_count': self.execution_count,
                    'payload': [],
                    'user_expressions': {},
            }

if __name__ == '__main__':
    from ipykernel.kernelapp import IPKernelApp
    IPKernelApp.launch_instance(kernel_class=ArmKernel)            