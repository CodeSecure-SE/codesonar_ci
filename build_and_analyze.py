# The intent of this script is to be used as a wrapper for the CodeSonar
# analyze command.  It will run the build and analyze commands and then parse the
# resulting output file to determine if there are any new issues.  If there
# are new issues, it will return a sarif file with the new findings.
# This script is intended to be used as part of a CI/CD pipeline.


import os
import subprocess
import sys
import urllib.parse
from datetime import datetime


debug = True

# first check if we have all the required arguments

if (len(sys.argv) < 1):
    print("Missing build command")
    sys.exit(1)

build_command = " ".join(sys.argv[1:])

print ("Build command: " + build_command)
all_ok=1

def check_env(s, t):
    global all_ok
    if os.getenv(s) is None:
        print("Missing " + s + " environment variable, should be set to " + t)
        all_ok=0   
    
    
# checking environment variables
check_env('CSONAR_HUB_URL', 'URL for CodeSonar HUB') 
check_env('CSONAR_HUB_USER', 'Username for CodeSonar HUB')
check_env('CSONAR_HUB_PASSWORD', 'Password for CodeSonar HUB')
check_env('CSONAR_CSHOME', 'Path to CodeSonar installation')
check_env('ROOT_TREE', 'Path to the project-tree in the CodeSonar HUB')
check_env('PROJECT_NAME', 'Name of the project in the CodeSonar HUB')
check_env('GITHUB_API_URL', 'URL for GitHub API')
check_env('GITHUB_TOKEN', 'Token for GitHub API')
check_env('GITHUB_CAFILE', 'Path to GitHub CA (cert) file')
check_env('GITHUB_REPO_URL', 'URL for GitHub repository')
check_env('PULL_REQUEST_NUMBER', 'Pull request ID from ${{ github.event.pull_request.number }}')
check_env('BRANCH_NAME', 'Name of the current branch, ${{ github.head_ref || github.ref_name }} ')
check_env('IS_PR', 'Set to true if this is a pull request, ${{ github.event_name == \'pull_request\' }}')
check_env('TARGET', 'Target branch for the pull request, ${{ github.base_ref || github.target_branch }}')

#TODO: Add GITLAB equivalents


if all_ok==0:
    print("Exiting, not all variables have been set!")
    sys.exit(1)

# create hub credentials
CSONAR_HUB_PW_FILE = os.path.join(os.getcwd(), 'hub_pw')
f = open (CSONAR_HUB_PW_FILE, "w")
f.write(os.getenv('CSONAR_HUB_PASSWORD'))
f.close()

target_project_aid = 0

# If this is a PR/MR, find the analysis-id of the latest analysis on the target branch
if os.getenv('IS_PR') == 'pull_request':
    link = "{\"limit\":1,\"orderBy\":[{\"analysisId\":\"DESCENDING\"}],\"columns\":[\"analysisId\"]}"
    query = "\"branch.name\"=\"" + os.getenv("TARGET") + "\"state=\"Finished\""
    
    command = os.getenv('CSONAR_CSHOME') + "/codesonar/bin/codesonar get -auth password -hubuser " + \
        os.getenv('CSONAR_HUB_USER') + " -hubpwfile " + CSONAR_HUB_PW_FILE + " " + \
        os.getenv('CSONAR_HUB_URL') + "/analysis_search.csv?sanlgrid_json=" + \
        urllib.parse.quote(link) + "\&query=" + urllib.parse.quote(query) + " -o - > result"
        
    if debug: 
        print ("Command: " + command)
    
    result = os.system(command)
    
 
    if result != 0:
        print ("Error retrieving analysis id")
        sys.exit(1)
    
    f = open("result", "r")
    target_project_aid = f.read().splitlines()[1]
    f.close()
 
    if debug:
        print ("Target project analysis id: " + target_project_aid)

#Perform the actual build
command = os.getenv('CSONAR_CSHOME') + "/codesonar/bin/codesonar build -clean " + \
os.getenv("PROJECT_NAME") + " -remote-archive \"/saas/*\" -foreground " + \
            " -auth password" + \
            " -hubuser " + os.getenv('CSONAR_HUB_USER') + " -hubpwfile " + CSONAR_HUB_PW_FILE + \
            " -project " + os.getenv("ROOT_TREE") + "/" + os.getenv("BRANCH_NAME") + \
            " -name \"" + datetime.now().strftime("%m/%d/%Y-%H:%M:%S") +"\"" + \
            " -conf-file conf/codesonar-release.conf" + \
            " " + os.getenv("CSONAR_HUB_URL") + " " + \
            build_command

if debug:
    print(command)

#result = os.system(command) 

if result != 0:
    print ("Problem running build command")
    sys.exit(1)

#Construct the properties
if os.getenv('IS_PR') == 'pull_request':
    property_pr_link = os.getenv('GITHUB_REPO_URL') + "/pull/" + os.getenv('PULL_REQUEST_NUMBER')
else:
    property_pr_link = "None"
        
if debug:
            print("PR Link: " + property_pr_link)

f = open (os.getenv("PROJECT_NAME") + ".prj_files/aid.txt", "r")
current_project_aid = f.read()
f.close()

if os.getenv('IS_PR') == 'pull_request':
    property_new_findings = os.getenv('CSONAR_HUB_URL') +"/search.html?query=" + \
        urllib.parse.quote("aid:"+str(current_project_aid) + " DIFFERENCE aid:" + str(target_project_aid)) + \
        "&scope=" + urllib.parse.quote("aid:" + str(current_project_aid)) + "&swarnings=BJAW"
else:
    property_new_findings = "None"
    
if debug:
    print("New findings: " + property_new_findings)
            
command = os.getenv('CSONAR_CSHOME') + "/codesonar/bin/codesonar analyze " + \
            os.getenv("PROJECT_NAME") + " -remote-archive \"/saas/*\" -foreground " + \
            " -auth password" + \
            " -hubuser " + os.getenv('CSONAR_HUB_USER') + " -hubpwfile " + CSONAR_HUB_PW_FILE + \
            " -project " + os.getenv("ROOT_TREE") + "/" + os.getenv("BRANCH_NAME") + \
            " -property New_findings \"" + property_new_findings + "\""\
            " -property PR_link \"" +  property_pr_link + "\"" \
            " -name \"" + datetime.now().strftime("%m/%d/%Y-%H:%M:%S") +"\"" + \
            " -conf-file conf/codesonar-release.conf" + \
            " " + os.getenv("CSONAR_HUB_URL") 

if debug:
    print(command)

result = os.system(command) 
if result != 0:
    print ("Problem running analyze command")
    sys.exit(1)             

# Download the new findings results in SARIF, if it is a pull request
if os.getenv('IS_PR') == 'pull_request':
    command = os.getenv('CSONAR_CSHOME') + "/codesonar/bin/codesonar get -auth password -hubuser " + \
        os.getenv('CSONAR_HUB_USER') + " -hubpwfile " + CSONAR_HUB_PW_FILE + " " + \
        "\"" +os.getenv('CSONAR_HUB_URL') + "/warning_detail_search.sarif?query=" + \
        urllib.parse.quote("aid:"+str(current_project_aid) + " DIFFERENCE aid:" + str(target_project_aid)) + \
        "&scope=" + urllib.parse.quote("aid:" + str(current_project_aid)) + "&swarnings=BJAW\"" + \
        " -o - > warnings.sarif"
    if debug: 
        print ("Command: " + command)
        
    result = os.system(command)
    
    if result != 0:
        print ("Error retrieving SARIF file")
        sys.exit(1)
        
    #Convert to summary
    command = os.getenv("CSONAR_CSHOME")+"/codesonar/bin/cspython " + \
        "/opt/codesonar-github/sarif_summary.py warnings.sarif " + \
        os.getenv("CSONAR_HUB_URL") + " " + \
        os.getenv("PROJECT_NAME") + " > warnings.md"
    result=os.system(command)
    
    if result != 0:
        print ("Error converting SARIF file to markdown")
        sys.exit(1)
        


# remove hub credentials
if not debug:
    os.remove(CSONAR_HUB_PW_FILE)
