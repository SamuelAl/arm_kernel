from enum import Enum
import yaml
from yaml.loader import SafeLoader
import re

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

class BlockType(Enum):
    INVALID = 0
    TEXT = 1
    CONFIG = 2
    MEM_FUNC = 4

class Preprocessor:

    @staticmethod
    def parse(text: str) -> dict:
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
                print(content)

        return {
            'type': block_type,
            'content': content,
        }
    
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

prep = Preprocessor()
prep.parse(CODE_1)


