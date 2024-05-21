import json
import sys

f = open (sys.argv[1], "r")
data = json.load(f)

for r in data["runs"]:
    for result in r["results"]:
        pl =result["locations"][0]["physicalLocation"]
        print(pl["artifactLocation"]["uri"] + " +" + str(pl["region"]["startLine"]) )
        print ("   Rule: " + result["ruleId"])
        print ("   Description: " + result["message"]["text"])
        print ("")
