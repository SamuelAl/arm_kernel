import re

show_bnf = """
show view[...] as (dec|hex)
"""

TEST = """
LDR R0, =random
>>> show registers[1-6] as dec
>>> show registers[1-6] as hex
>>> show registers
"""

show_re = re.compile(r"^>>>\s+show\s+(?P<view>[a-zA-Z]+)(?P<context>\[([a-zA-Z0-9,\-:]*)\])?(\s+as\s+(?P<format>dec|hex))?")

for line in TEST.splitlines():
    line = line.lstrip()
    match = show_re.search(line)
    if match is not None:
        print(match.groupdict())