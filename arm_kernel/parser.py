from pyparsing import Word, alphas

# define grammar of a greeting
greet = Word(alphas) + "," + Word(alphas) + "!"

hello = "Hello, World!"
print(hello, "->", greet.parse_string(hello))

mem_bnf = """
statements
    statement
    statements statement
    empty
statement
    label type := value
array
    [ elements ]
elements
    value
    elements , value
value
    string
    number
    object
    array
"""

