from __future__ import print_function
from sys import implementation
from ipykernel.kernelbase import Kernel
from emulator import Emulator

def state_to_table(state_dict):
    table = ""
    for key, value in state_dict.items():
        table += "<tr><th>%s</th><th>%s</th></tr>" % (key,value)
    result = "<table>" + table + "</table>"
    return result


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

    def do_execute(self, code, silent, store_history=True, user_expressions=None, allow_stdin=False):
        if not silent:
            state = self.emulator.execute_code(code)
            stream_content = {
                'metadata': {},
                'data': {'text/html': state_to_table(state)}
                }
            self.send_response(self.iopub_socket, 'display_data', stream_content)
            
            return {'status': 'ok',
                    # The base class increments the execution count
                    'execution_count': self.execution_count,
                    'payload': [],
                    'user_expressions': {},
            }

if __name__ == '__main__':
    from ipykernel.kernelapp import IPKernelApp
    IPKernelApp.launch_instance(kernel_class=ArmKernel)            