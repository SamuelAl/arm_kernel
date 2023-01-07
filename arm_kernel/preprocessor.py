from enum import Enum
import re

CODE_1 = """$$content:mem-ro
label1:
    .word 1,2,3
label2:
    .asciiz "Samuel"
"""

class BlockType(Enum):
    INVALID = 0
    TEXT = 1
    MEM_RO = 2
    MEM_RW = 3
    MEM_FUNC = 4

rx_dict = {
    'memory_labels': re.compile(r'(?P<label>[^\s]+:)')
}

class Preprocessor:

    def __init__(self):
        # Initializer
        print("Preprocessor")

    def parse(self, text: str) -> dict:

        # remove whitespace from beginning of line
        text = text.lstrip()
        #separate lines
        lines = text.splitlines()
        if len(lines) < 1:
            return {'type': BlockType.INVALID}
        # first line will indicate block type
        block_type = self.parse_type(lines[0])
        content = {}
        match block_type:
            case BlockType.MEM_RO:
                content = self.parse_memory(lines[1:])
                print(content)

        return {
            'type': block_type,
            'content': '\n'.join(lines[1:]),
        }
    
    def parse_type(self, line: str) -> BlockType:
        line = line.strip()
        match line:
            case "$$content:mem-ro":
                return BlockType.MEM_RO
            case "$$content:mem-rw":
                return BlockType.MEM_RW
            case _:
                return BlockType.TEXT

    def parse_memory(self, lines: list[str]) -> dict:
        labels = []
        for line in lines:
            label = rx_dict['memory_labels'].search(line)
            if label is not None:
                labels.append(label)
                print(label.group("label"))

        print(labels)
        return {}

prep = Preprocessor()
prep.parse(CODE_1)


