from preprocessor import *

CODE_1 = """$$content:mem-ro"""

def test_preprocessor():
    prep = Preprocessor()
    assert prep.parse(CODE_1) == (BlockType.CONFIG, '')