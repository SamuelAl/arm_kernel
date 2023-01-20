from fnmatch import fnmatch
import pynumparser

# TEST1 = 'r[10,11,12]'
# TARGET= ["r" + str(i) for i in range(13)]
# TARGET.append('sp')

# filtered = [x for x in TARGET if fnmatch(x, TEST1)]
# print(filtered)

TEST2 = "1-5"
parser = pynumparser.NumberSequence()
seq = parser.parse(text=TEST2)
print(seq)

