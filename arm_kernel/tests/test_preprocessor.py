from arm_kernel.preprocessor import Preprocessor
from collections import namedtuple

def test_hexify_immediate_values():
    TestCase = namedtuple("TestCase", ("input", "want"))
    tests = [
        TestCase("#10", hex(10))
    ]
    for test in tests:
        got = Preprocessor.hexify_immediate_values(test.input)
        assert got == test.want