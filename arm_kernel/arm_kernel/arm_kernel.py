from __future__ import print_function
from sys import implementation

from ipykernel.kernelbase import Kernel
import logging

from arm_kernel.emulator import Emulator
from arm_kernel.preprocessor import Preprocessor, BlockType
from arm_kernel.view import View

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
    
    view = View()

    
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.emulator = Emulator()

    def _execute_code(self, content: dict):
        
        try:
            state = self.emulator.execute_code(content["code"])
            if len(content["views"]) > 0:
                stream_content = {
                    'metadata': {},
                    'data': {'text/html': self.view.get_view(content["views"][0], state)}
                }
                # stream_content = {
                #     'metadata': {},
                #     'data': {'text/plain': self.emulator.mem._items.items()}
                # }
                self.send_response(self.iopub_socket, 'display_data', stream_content)
        except Exception as error:
            stream_content = {
                'metadata': {},
                'data': {'text/html': f"<p>Error: {str(error)}</p>"}
            }
            self.send_response(self.iopub_socket, 'display_data', stream_content)
        


    def _handle_config(self, config: dict):
        # For now only handle memory:
        labels = "labels: "
        if config.get("memory") is not None:
            mem_config = config["memory"]
            for item in mem_config.get("items"):
                self.emulator.add_memory_item(item)

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
          