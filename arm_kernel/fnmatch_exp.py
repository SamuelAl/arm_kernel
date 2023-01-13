from fnmatch import fnmatch

TEST1 = 'r[1-3,5]'
TARGET= ["r" + str(i) for i in range(13)]
TARGET.append('sp')

filtered = [x for x in TARGET if fnmatch(x, TEST1)]
print(filtered)