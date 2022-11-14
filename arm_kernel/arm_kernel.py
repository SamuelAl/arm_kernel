from __future__ import print_function
from sys import implementation
from ipykernel.kernelbase import Kernel
from unicorn import *
from unicorn.arm_const import *
from keystone import *

# memory address where emulation starts
ADDRESS    = 0x10000

# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))

def execute_code(code):
    try:

        # Initialize engine in X86-32bit mode.
        ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
        encoding, count = ks.asm(code)
        print("%s = %s (number of statements: %u)" % (code, encoding, count))
        assembled = bytes(encoding)
        print(assembled)
        
        # Initialize emulator in ARM mode
        mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)  

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, assembled)  

        # initialize machine registers
        mu.reg_write(UC_ARM_REG_R0, 0x1234)
        mu.reg_write(UC_ARM_REG_R1, 0x6789)
        mu.reg_write(UC_ARM_REG_APSR, 0xFFFFFFFF) #All application flags turned on

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing one instruction at ADDRESS with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code, begin=ADDRESS, end=ADDRESS)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(assembled))

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        r0 = mu.reg_read(UC_ARM_REG_R0)
        r1 = mu.reg_read(UC_ARM_REG_R1)
        print(">>> R0 = 0x%x" %r0)
        print(">>> R1 = 0x%x" %r1)
        return r0


    except UcError as e:
        print("ERROR: %s" % e)

class ArmKernel(Kernel):
    implementation = 'ARM Assembly'
    implementation_version = '1.0'
    language = 'ARM Assembly'
    language_version = '0.1'
    language_info = {
        'name': 'Any text',
        'mimetype': 'text/plain',
        'file_extension': '.txt',
    }
    banner = "ARM Assembly - code an ARM CPU"

    counter = 0

    def do_execute(self, code, silent, store_history=True, user_expressions=None, allow_stdin=False):
        if not silent:
            # r0 = execute_code(code)
            stream_content = {'name': 'stdout', 'text': "Counter %d" % self.counter}
            self.counter += 1
            self.send_response(self.iopub_socket, 'stream', stream_content)
            
            return {'status': 'ok',
                    # The base class increments the execution count
                    'execution_count': self.execution_count,
                    'payload': [],
                    'user_expressions': {},
            }

if __name__ == '__main__':
    from ipykernel.kernelapp import IPKernelApp
    IPKernelApp.launch_instance(kernel_class=ArmKernel)            