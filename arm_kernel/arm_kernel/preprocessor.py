from enum import Enum
import yaml
from yaml.loader import SafeLoader
from arm_kernel.memory import MemoryItem, MemoryType, ItemType
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
CODE_2 = """
LDR R0, =test
LDR R1, [R0]
LDR R2, [R0, #8]
MOV R0, R1
>>> show registers
"""

show_re = re.compile(r"^>>>\s+show\s+(?P<view>[a-zA-Z]+)(\[(?P<context>[a-zA-Z0-9,\-:]*)\])?(\s+as\s+(?P<format>dec|hex|bin))?")
decimal_imm_re = re.compile(r'#\d\d+')

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
                views, cleaned_code = Preprocessor.process_code(text)
                content = {
                    "code": cleaned_code,
                    "views": views
                }

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
        parsed_yaml = yaml.load(config, Loader=SafeLoader)
        parsed = {}
        if parsed_yaml.get("memory") is not None:
            parsed["memory"] = Preprocessor.parse_memory_config(parsed_yaml["memory"])
        return parsed

    @staticmethod
    def parse_memory_config(config: dict) -> dict:
        items = config.get("items")
        items_ls = []
        if items is None:
            return {}
        for label in items.keys():
            item = Preprocessor.item_from_config(label, items[label])
            items_ls.append(item)
        return {
            "items": items_ls
        }
    
    @staticmethod
    def item_from_config(label: str, data: dict) -> MemoryItem:
        '''Creates a MemoryItem from a config dict.'''

        item_type = Preprocessor.get_item_type(data["type"])
        memory_type = Preprocessor.get_memory_type(data["access"])

        if item_type is ItemType.SPACE:
            return MemoryItem(label, item_type, memory_type, data["size"])
        
        size = data.get("size")
        if size is None:
            size = 1
        return MemoryItem(label, item_type, memory_type, size, data["content"])

    @staticmethod
    def get_item_type(val: str) -> ItemType:
        '''Transform a type string into an ItemType value.'''

        match val.lower():
            case 'space':
                return ItemType.SPACE
            case 'word':
                return ItemType.WORD
            case 'hword':
                return ItemType.HWORD
            case 'byte':
                return ItemType.BYTE
            case 'int':
                return ItemType.INT
            case ('ascii' | 'string'):
                return ItemType.STRING
            case _ :
                raise ValueError(f"Invalid item type {val}.")

    @staticmethod
    def get_memory_type(val: str) -> ItemType:
        '''Transform an access string into a MemoryType value.'''

        match val.lower():
            case 'ro':
                return MemoryType.RO
            case 'rw':
                return MemoryType.RW
            case _ :
                raise ValueError(f"Invalid memory access type {val}.")

    @staticmethod
    def hexify_immediate_values(line: str) -> str:
        values = decimal_imm_re.findall(line)
        for value in values:
            dec_val = int(value[1:])
            hex_val = '#' + hex(dec_val)
            line = line.replace(value, hex_val)
        return line

    @staticmethod
    def process_code(code: str):
        lines = code.splitlines()
        cleaned_code = []
        views = []
        for line in lines:
            # Substitute decimal immediate values with hex equivalent.
            line = Preprocessor.hexify_immediate_values(line)
            match = show_re.search(line)
            if match is not None:
                views.append(match.groupdict())
            else:
                cleaned_code.append(line)
        
        return views, '\n'.join(cleaned_code)


