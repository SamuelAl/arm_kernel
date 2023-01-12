from enum import Enum
import yaml
from yaml.loader import SafeLoader

CODE_1 = """__config__
memory:
    items:
        label1:
            type: word
            content: [1,2,3,4]
            access: ro
        label2:
            type: byte
            content: [1,2,3,4]
            access: rw
"""
CODE_2 = """
LDR R0, =test
LDR R1, [R0]
LDR R2, [R0, #8]
MOV R0, R1
"""

class BlockType(Enum):
    INVALID = 0
    TEXT = 1
    CONFIG = 2
    MEM_FUNC = 4

class Preprocessor:

    @staticmethod
    def parse(text: str) -> tuple:
        # remove whitespace from beginning of line.
        text = text.lstrip()

        # Get first line.
        partition = text.split('\n', 1)
        if len(partition) < 1:
            return {'type': BlockType.INVALID}
        # first line will indicate block type
        block_type = Preprocessor.parse_type(partition[0])

        content = {}
        match block_type:
            case BlockType.CONFIG:
                content = Preprocessor.parse_config(partition[1])
            case BlockType.TEXT:
                content = text

        return (
            block_type,
            content
        )
    
    @staticmethod
    def parse_type(line: str) -> BlockType:
        line = line.strip()
        match line:
            case "__config__":
                return BlockType.CONFIG
            case _:
                return BlockType.TEXT

    @staticmethod
    def parse_config(config: str) -> dict:
        # Parse YAML config.
        config = config.replace('\t', "  ")
        parsed = yaml.load(config, Loader=SafeLoader)
        
        return parsed


print(Preprocessor.parse(CODE_2))


