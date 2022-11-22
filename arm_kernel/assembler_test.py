from __future__ import print_function
from keystone import *

TEST_CODE = """
testArray1: \n
 .word 1, 2, 3 @ row 0\n
testArray2: \n
 .word 4, 5, 6 @ row 0\n
hello:
 .string "Hello"
"""

assembler = Ks(KS_ARCH_ARM, KS_MODE_ARM)

encoding, count = assembler.asm(TEST_CODE)
print(encoding)