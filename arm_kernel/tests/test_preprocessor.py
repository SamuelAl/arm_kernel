from arm_kernel.preprocessor import Preprocessor
from collections import namedtuple

def test_hexify_immediate_values():
    TestCase = namedtuple("TestCase", ("input", "want"))
    tests = [
        TestCase("#10", f'#{hex(10)}'),
        TestCase("mov r0, #1", "mov r0, #1"),
        TestCase("mov r0, #10", "mov r0, #0xa"),
        TestCase("mov r0, #26", f"mov r0, #{hex(26)}"),
        TestCase("ldr r0, =26", f"ldr r0, ={hex(26)}"),
        TestCase("ldr r0, =1", f"ldr r0, =1"),
        TestCase("ldr r0, =label", f"ldr r0, =label"),
        TestCase("ldr r0, =1label", f"ldr r0, =1label"),
        TestCase("ldr r0, =10label", f"ldr r0, =10label"),
    ]
    for test in tests:
        got = Preprocessor.hexify_immediate_values(test.input)
        assert got == test.want