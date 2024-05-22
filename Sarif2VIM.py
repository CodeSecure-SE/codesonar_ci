import json
import sys
import subprocess
import os
import urllib.parse

# get the current branch name
branch = subprocess.run(['git', 'rev-parse',  '--abbrev-ref', 'HEAD'], stdout=subprocess.PIPE).stdout.decode('utf-8')

# get the link to the latest analysis with that branch-name set
link = "{\"limit\":1,\"orderBy\":[{\"analysisId\":\"DESCENDING\"}],\"columns\":[\"analysisId\"]}"
query = "\"branch_name\"=\"" + branch + "\"state=\"Finished\""
command = os.getenv('CSONAR_CSHOME') + "/codesonar/bin/codesonar get -auth certificate -hubuser " + \
        os.getenv('CSONAR_HUB_USER') + \
        os.getenv('CSONAR_HUB_URL') + "/analysis_search.csv?sanlgrid_json=" + \
        urllib.parse.quote(link) + "\&query=" + urllib.parse.quote(query) + " -o - > result"

print(command)
result = os.system(command)


if result != 0:
    print ("Error retrieving analysis id")
    sys.exit(1)

f = open("result", "r")
resultFile = f.read()
if len(resultFile.splitlines()) < 2:
    print ("No existing analysis found, exiting")
    sys.exit(1)
else: 
    target_project_aid = resultFile.splitlines()[1]

f.close()

command = os.getenv('CSONAR_CSHOME') + "/codesonar/bin/codesonar get -auth certificate -hubuser " + \
        os.getenv('CSONAR_HUB_USER') + \
        os.getenv('CSONAR_HUB_URL') + "/analysis/" + target_project_aid + ".sarif -o " + target_project_aid + ".sarif"

print(command)

# Read the SARIF File
f = open (target_project_aid + ".sarif", "r")
data = json.load(f)

for r in data["runs"]:
    for result in r["results"]:
        pl =result["locations"][0]["physicalLocation"]
        print(pl["artifactLocation"]["uri"] + " +" + str(pl["region"]["startLine"]) )
        print ("   Rule: " + result["ruleId"])
        print ("   Description: " + result["message"]["text"])
        print ("   Link: " + result["hostedViewerUri"])
        print ("")
