import re
import sys

with open(sys.argv[1], 'r') as file:
  s = file.read()


t = re.sub(r"java\",\"uriBaseId\":\"SRCROOT0\"","java\"\n",s)
print(t)