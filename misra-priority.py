import sys
import os
import csv
import locale


# use user's default settings
locale.setlocale(locale.LC_ALL, '')


# This script takes in a configuration file with MISRA WARNING_FILTER and
# adds priority:= to each rule
# it downloads the configuration file from the hub
#
# Requirements:
# - codesonar in the path

# Configuration paramaters
HUB = "https://partnerdemo.codesonar.com"
HUBUSER = "testuser"
AUTH = "password"

# This is the mapping of the priorities.
priorities = {}
priorities['Mandatory'] = "Mandatory"
priorities['Required'] = "Required"
priorities['Advisory'] = "Advisory"

if '-hub' in sys.argv:
    HUB = sys.argv[sys.argv.index('-hub') + 1]
    sys.argv.remove('-hub')
    sys.argv.remove(HUB)

if '-hubuser' in sys.argv:
    HUBUSER = sys.argv[sys.argv.index('-hubuser') + 1]
    sys.argv.remove('-hubuser')
    sys.argv.remove(HUBUSER)

if '-auth' in sys.argv:
    AUTH = sys.argv[sys.argv.index('-auth') + 1]
    sys.argv.remove('-auth')
    sys.argv.remove(AUTH)


if len(sys.argv) < 2:
    print ("Usage: python misra-priority.py <config-file> ")
    sys.exit(1)


# Step 1: Download the mapping file from the hub
COMMAND = "codesonar get -HUBUSER " + HUBUSER + " -auth " + AUTH + " " + \
        HUB + "/install/codesonar/doc/html/WarningClasses/Misra2012-mapping.csv"

os.system(COMMAND)


with open("Misra2012-mapping.csv", encoding="utf8", mode="r") as csv_file:
    csv_reader = csv.DictReader(csv_file)
    next(csv_reader)
    mapping = list(csv_reader)

#Step 2: Calculate the highest priroty per CodeSonar rule
cso_mapping = {}

for r in mapping:
    if not r['CodeSonar Class Name'] in cso_mapping:
        cso_mapping[r['CodeSonar Class Name']] = r['Category']
    else: 
        if (cso_mapping[r['CodeSonar Class Name']] == "Required" \
                or cso_mapping[r['CodeSonar Class Name']] == "Advisory") \
                and r['Category'] == "Mandatory":
            cso_mapping[r['CodeSonar Class Name']] = "Mandatory"
        elif cso_mapping[r['CodeSonar Class Name']] == "Advisory" \
                 and r['Category'] == "Required":
            cso_mapping[r['CodeSonar Class Name']] = "Required"
            
# Step 3: Read in the configuration file line by line and translate
with (open(sys.argv[1], encoding="utf8", mode="r")) as config_file:
    for line in config_file:
        line = line.rstrip()
        TRANSLATED = 0
        for cl, prio in cso_mapping.items():
            if (cl in line and "allow" in line):
                print (line)
                new_line = line.replace(" allow ", " priority:=\"" + \
                                        priorities[prio] + "\" ")
                print (new_line)
                TRANSLATED = 1

        if not TRANSLATED:
            print(line)
        