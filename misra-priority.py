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
HUBUSER = "mhermeling"

# This is the mapping of the priorities.
priorities = {}
priorities['Mandatory'] = "P0_Mandatory"
priorities['Required'] = "P1_Required"
priorities['Advisory'] = "P2_Advisory"



if len(sys.argv) < 2:
    print ("Usage: python misra-priority.py <config-file> ")
    sys.exit(1)


# Step 1: Download the mapping file from the hub
COMMAND = "codesonar get -HUBUSER " + HUBUSER + " -auth certificate " + \
        HUB + "/install/codesonar/doc/html/WarningClasses/Misra2012-mapping.csv"

print ("Getting MISRA C 2012 mapping file from the hub")
os.system(COMMAND)

with open("Misra2012-mapping.csv", "r") as csv_file:
    csv_reader = csv.DictReader(csv_file)
    next(csv_reader)
    mapping = list(csv_reader)


#Step 2: Calculate the highest priroty per CodeSonar rule
cso_mapping = {}

for r in mapping:
        if not r['CodeSonar Class Name'] in cso_mapping:
            cso_mapping[r['CodeSonar Class Name']] = r['Category']
        else: 
            if (cso_mapping[r['CodeSonar Class Name']] == "Required" or cso_mapping[r['CodeSonar Class Name']] == "Advisory") and r['Category'] == "Mandatory":
                cso_mapping[r['CodeSonar Class Name']] = "Mandatory"
            elif cso_mapping[r['CodeSonar Class Name']] == "Advisory" and r['Category'] == "Required":
                cso_mapping[r['CodeSonar Class Name']] = "Required"
            
# Step 3: Read in the configuration file line by line and translate
with (open(sys.argv[1], "r")) as config_file:
    for line in config_file:
        line = line.rstrip()
        translated = 0
        for r in cso_mapping:
            if r in line:
                new_line = line.replace(" allow ", " allow priority:=\"" + priorities[cso_mapping[r]] + "\" ")
                print (new_line)
                translated = 1

        if not translated:
                print(line)
        