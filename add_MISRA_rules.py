import csv
import sys
import os.path

# This script takes in a SARIF file and the CodeSonar-to-MISRA mapping csv file
# and outputs the SARIF file with the MISRA-rules added to the rules names
# This is only a quick prototype that replaces the string of the CodeSonar warning.
# A more elaborate implementation would be to parse the JSON correctly.

if len(sys.argv) < 3:
    print ("Usage: python add_MISRA_rules.py <SARIF file> <CodeSonar-to-MISRA mapping file>")
    sys.exit(1)

sarifFile = sys.argv[1]
mappingFile = sys.argv[2]

if not os.path.isfile(sarifFile):
    print ("File not found: "+sarifFile)
    sys.exit(1) 

if not os.path.isfile(mappingFile):
    print ("File not found: "+mappingFile)
    sys.exit(1)

# Read in the csv file
with open(mappingFile, "r") as csv_file:
    csv_reader = csv.reader(csv_file)
    next(csv_reader)
    mapping = list(csv_reader)  
#    print (mapping[0][0] + "-" + mapping[0][8])



# Read in the SARIF file
with open(sarifFile, "r") as sarif_file:
    for line in sarif_file:
        for i in range(len(mapping)):
            if mapping[i][8] in line:
                line = line.replace(mapping[i][8], mapping[i][0] + "-" + mapping[i][8])
        print (line)
        

