# The intent of this script is to be used as a wrapper for the CodeSonar
# analyze command.  It will run the build and analyze commands and then parse the
# resulting output file to determine if there are any new issues.  If there
# are new issues, it will return a sarif file with the new findings.
# This script is intended to be used as part of a CI/CD pipeline.


import os
import subprocess
import sys
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime
import csv



Debug = True

CWE = False
MISRA = False
GitLab = False
GitHub = False

transcodeFile = ""

# first check if we have all the required arguments

if (len(sys.argv) < 2):
    print("Insufficient parameters, exiting")
    print("Usage: build_and_analyze.py [options] <conf-file> <build-command>")
    print("Script outputs:")
    print("  - warnings.sarif: SARIF file with the warnings in PR (if triggered by a PR), or all visible warnings")
    print("  - warnings.md: Markdown related to the above")
    print("  - warnings-translate.sarif: SARIF file with CWE/MISRA warnings (only if one or more of the options -cwe or -misra are used)") 
    sys.exit(1)

if '-cwe' in sys.argv:
    CWE=True
    sys.argv.remove('-cwe')

if ('-misra' in sys.argv):
    MISRA=True
    sys.argv.remove('-misra')
    
preset = ""
# Check for presets
if '-preset' in sys.argv:
    i = sys.argv.index("-preset")
    preset = "- preset " + sys.argv[i+1]
    sys.argv.remove(sys.argv[i+1])
    sys.argv.remove(sys.argv[i]);  
    

uploadFlag = '-remote-archive \"/saas/*\"'
if ('-noupload' in sys.argv):
    uploadFlag = ''
    sys.argv.remove('-noupload')

conf_file = sys.argv[1]
build_command=[]
build_command = sys.argv[2:]


all_ok=1

def check_env(s, t):
    global all_ok
    if os.getenv(s) is None:
        print("Missing " + s + " environment variable, should be set to " + t)
        all_ok=0   

# checking for GitLab variables
if os.getenv("CI_COMMIT_SHA") is not None:
    GitLab=True
    print("Reading GitLab environment variables")
    if os.getenv("REQUEST_NUMBER") is None:
        os.environ['REQUEST_NUMBER'] = os.getenv('CI_MERGE_REQUEST_IID', "None")
    if os.getenv("BRANCH_NAME") is None:
        os.environ['BRANCH_NAME'] = os.getenv('CI_COMMIT_REF_NAME', "None")
    if os.getenv("IS_PR") is None:
           os.environ['IS_PR'] = os.getenv('CI_PIPELINE_SOURCE', "None")
    if os.getenv("TARGET") is None:
        os.environ['TARGET'] = os.getenv('CI_MERGE_REQUEST_TARGET_BRANCH_NAME', "None")
    if os.getenv("COMMIT_HASH") is None:
        os.environ['COMMIT_HASH'] = os.getenv('CI_COMMIT_SHA', "None")
    if os.getenv("TOKEN") is None:
        os.environ['TOKEN'] = os.getenv('CI_JOB_TOKEN', "None")

# checking for GitHub variables
if os.getenv("GITHUB_ACTION") is not None:
    GitHub=True
    if "REQUEST_NUMBER" not in os.environ:
        ref = os.getenv('GITHUB_REF_NAME')
        if ref.endswith("/merge"):
            os.environ['REQUEST_NUMBER'] = ref.split("/")[0]
        else:
            os.environ['REQUEST_NUMBER'] = "None"
  
    if "BRANCH_NAME" not in os.environ:
        if os.getenv('GITHUB_HEAD_REF') is not None:
            os.environ['BRANCH_NAME'] = os.getenv('GITHUB_HEAD_REF')
        else:
            os.environ['BRANCH_NAME'] = os.getenv('GITHUB_REF_NAME') 
    if "IS_PR'" not in os.environ:
           os.environ['IS_PR'] = os.getenv('GITHUB_EVENT_NAME')
    if "TARGET" not in os.environ:
        os.environ['TARGET'] = os.getenv('GITHUB_BASE_REF')
    if "COMMIT_HASH" not in os.environ:
        os.environ['COMMIT_HASH'] = os.getenv('GITHUB_SHA')
    if "TOKEN" not in os.environ:
        os.environ['TOKEN'] = os.getenv('GITHUB_TOKEN')    


# checking environment variables
check_env('CSONAR_HUB_URL', 'URL for CodeSonar HUB') 
check_env('CSONAR_HUB_USER', 'Username for CodeSonar HUB')
check_env('CSONAR_HUB_PASSWORD', 'Password for CodeSonar HUB')
check_env('CSONAR_CSHOME', 'Path to CodeSonar installation')
check_env('ROOT_TREE', 'Path to the project-tree in the CodeSonar HUB')
check_env('PROJECT_NAME', 'Name of the project in the CodeSonar HUB')
check_env('TOKEN', 'Token API')
#check_env('CAFILE', 'Path to CA (cert) file')
check_env('REPO_URL', 'URL for repository')
check_env('REQUEST_NUMBER', 'Pull/Merge request ID')
check_env('BRANCH_NAME', 'Name of the current branch ')
check_env('IS_PR', 'Set to true if this is a pull/merge request')
check_env('TARGET', 'Target branch for the pull/merge request')
check_env("COMMIT_HASH", "Commit hash")


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
print("IS_PR: " +os.getenv('IS_PR'))   
if os.getenv('IS_PR') == 'pull_request' or os.getenv('IS_PR') == 'merge_request_event':
    
    link = "{\"limit\":1,\"orderBy\":[{\"analysisId\":\"DESCENDING\"}],\"columns\":[\"analysisId\"]}"
    query = "\"branch_name\"=\"" + os.getenv("TARGET") + "\"state=\"Finished\""

    command = os.getenv('CSONAR_CSHOME') + "/codesonar/bin/codesonar get -auth password -hubuser " + \
        os.getenv('CSONAR_HUB_USER') + " -hubpwfile " + CSONAR_HUB_PW_FILE + " " + \
        os.getenv('CSONAR_HUB_URL') + "/analysis_search.csv?sanlgrid_json=" + \
        urllib.parse.quote(link) + "\&query=" + urllib.parse.quote(query) + " -o - > result"

    if Debug: 
        print ("Command: " + command)

    result = os.system(command)


    if result != 0:
        print ("Error retrieving analysis id")
        sys.exit(1)

    f = open("result", "r")
    resultFile = f.read()
    if len(resultFile.splitlines()) < 2:
        print ("No existing analysis found, continuing")
        target_project_aid = str("0")
    else: 
        target_project_aid = resultFile.splitlines()[1]
    f.close()

    if Debug:
        print ("Target project analysis id: " + str(target_project_aid))
namestr = datetime.now().strftime("%m/%d/%Y-%H:%M:%S")

#Perform the actual build
if (uploadFlag == ""):
    command = [os.getenv('CSONAR_CSHOME') + "/codesonar/bin/codesonar", 
                      "build",
                      "-clean",
                      os.getenv("PROJECT_NAME"),
                        "-foreground",
                        "-auth", "password", 
                        "-hubuser", os.getenv('CSONAR_HUB_USER'),
                        "-hubpwfile", CSONAR_HUB_PW_FILE,
                        "-project", os.getenv("ROOT_TREE") + "/" + os.getenv("BRANCH_NAME"),
                        "-name", namestr,
                        "-conf-file", conf_file,
                        os.getenv("CSONAR_HUB_URL")] + build_command
else:
       command = [os.getenv('CSONAR_CSHOME') + "/codesonar/bin/codesonar", 
                      "build",
                      "-clean",
                      os.getenv("PROJECT_NAME"),
                        "-remote-archive",  "\"/saas/*\"",
                        "-foreground",
                        "-auth", "password", 
                        "-hubuser", os.getenv('CSONAR_HUB_USER'),
                        "-hubpwfile", CSONAR_HUB_PW_FILE,
                        "-project", os.getenv("ROOT_TREE") + "/" + os.getenv("BRANCH_NAME"),
                        "-name", namestr,
                        "-conf-file", conf_file,
                        os.getenv("CSONAR_HUB_URL")] + build_command

p = subprocess.Popen(command, shell=False)
result = p.wait()

if Debug:
    print(command)


if result != 0:
    print ("Problem running build command")
    sys.exit(1)

#Construct the properties
if os.getenv('IS_PR') == 'pull_request' or os.getenv('IS_PR') == 'merge_request_event':
    property_pr_link = os.getenv('REPO_URL') + "/pull/" + os.getenv('REQUEST_NUMBER')
elif os.getenv('IS_PR') == 'merge_request_event':
    property_pr_link = os.getenv('REPO_URL') + "/merge_requests/" + os.getenv('REQUEST_NUMBER')
else:
    property_pr_link = "Not available"

if Debug:
            print("PR Link: " + property_pr_link)

f = open (os.getenv("PROJECT_NAME") + ".prj_files/aid.txt", "r")
current_project_aid = f.read()
print(" Current project aid: " + str(current_project_aid))
f.close()

if os.getenv('IS_PR') == 'pull_request' or os.getenv('IS_PR') == 'merge_request_event':
    property_new_findings = os.getenv('CSONAR_HUB_URL') +"/search.html?query=" + \
        urllib.parse.quote("aid:"+str(current_project_aid) + " DIFFERENCE aid:" + str(target_project_aid)) + \
        "&scope=" + urllib.parse.quote("aid:" + str(current_project_aid)) + "&swarnings=BJAW"
else:
    property_new_findings = "Not available"

property_commit_link = os.getenv('REPO_URL') + "/commit/" + os.getenv('COMMIT_HASH')

#Make sure the connection is closed
os.system(os.getenv('CSONAR_CSHOME') + "/codesonar/bin/codesonar get -auth password -hubuser " + \
        os.getenv('CSONAR_HUB_USER') + " -hubpwfile " + CSONAR_HUB_PW_FILE + " " + \
        os.getenv('CSONAR_HUB_URL') + "/command/close/" + str(current_project_aid) + "/")

if Debug:
    print("New findings: " + property_new_findings)


if os.getenv('TARGET') == "":
   targetStr="None"
else: 
    targetStr=os.getenv('TARGET')

commandstr = os.getenv('CSONAR_CSHOME') + "/codesonar/bin/codesonar analyze " + \
     os.getenv("PROJECT_NAME") + " " + uploadFlag + " -foreground " +  preset + \
            " -auth password" + \
            " -hubuser " + os.getenv('CSONAR_HUB_USER') + " -hubpwfile " + CSONAR_HUB_PW_FILE + \
            " -project " + os.getenv("ROOT_TREE") + "/" + os.getenv("BRANCH_NAME") + \
            " -property New_findings \"" + property_new_findings + "\"" +\
            " -property PR_link \"" +  property_pr_link + "\"" +\
            " -property target_branch \"" + targetStr + "\"" +\
            " -property commit_link \"" + property_commit_link + "\"" +\
            " -property branch_name \"" + os.getenv("BRANCH_NAME") + "\"" +\
            " -name \"" + namestr +"\"" + \
            " -conf-file " + conf_file + \
            " -srcroot ." + \
            " " + os.getenv("CSONAR_HUB_URL") 

if Debug:
    print(commandstr)

result = os.system(commandstr) 
if result != 0:
    print ("Problem running analyze command")
    sys.exit(1)             

# Download the new findings results in SARIF, if it is a pull request
if os.getenv('IS_PR') == 'pull_request' or os.getenv('IS_PR') == 'merge_request_event':
    # Pull just the changes
    commandstr = os.getenv('CSONAR_CSHOME') + "/codesonar/bin/codesonar get -auth password -hubuser " + \
        os.getenv('CSONAR_HUB_USER') + " -hubpwfile " + CSONAR_HUB_PW_FILE + " " + \
        " \"" +os.getenv('CSONAR_HUB_URL') + "/warning_detail_search.sarif?filter=" + urllib.parse.quote("\"active not clustered\"") + "&query=" + \
        urllib.parse.quote("aid:"+str(current_project_aid) + " DIFFERENCE aid:" + str(target_project_aid)) + \
        "&scope=" + urllib.parse.quote("aid:" + str(current_project_aid)) + "&swarnings=BJAW\"" + \
        " -o - > warnings.sarif"
    if Debug: 
        print ("Command: " + commandstr)

    result = os.system(commandstr)

    if result != 0:
        print ("Error retrieving SARIF file")
        print (commandstr)
        sys.exit(1)

    #Convert to summary
    commandstr = os.getenv("CSONAR_CSHOME")+"/codesonar/bin/cspython " + \
        "/opt/codesonar-github/sarif_summary.py warnings.sarif " + \
        os.getenv("CSONAR_HUB_URL") + " " + \
        os.getenv("PROJECT_NAME") + " > warnings.md"
    result=os.system(commandstr)

    if result != 0:
        print ("Error converting SARIF file to markdown")
        print (commandstr)
        sys.exit(1)
else:
    # Pull everything as a summary
    commandstr = os.getenv('CSONAR_CSHOME') + "/codesonar/bin/codesonar dump_warnings.py -auth password -hubuser " + \
        os.getenv('CSONAR_HUB_USER') + " -hubpwfile " + CSONAR_HUB_PW_FILE + " " + \
        "--hub " + os.getenv('CSONAR_HUB_URL') + " --project-file " + os.getenv("PROJECT_NAME") + ".prj --visible-warnings \"active not clustered\" --sarif -o warnings.sarif" 
    result=os.system(commandstr)

    if result != 0:
        print ("Error Pulling data from HUB")
        print (commandstr)
        sys.exit(1)


if result != 0:
    print ("Error pulling the CWE mapping file")
    print (commandstr)
    sys.exit(1)


# Last thing to do is to add CWE or MISRA namings into the SARIF file
if MISRA:
      # this is for the MISRA mapping in the SARIF file if desired
    commandstr = os.getenv('CSONAR_CSHOME') + "/codesonar/bin/codesonar get   -auth password -hubuser " + \
        os.getenv('CSONAR_HUB_USER') + " -hubpwfile " + CSONAR_HUB_PW_FILE + " " + \
        "https://partnerdemo.codesonar.com/install/codesonar/doc/html/WarningClasses/Misra2012-mapping-broad.csv"
    result=os.system(commandstr)
    transcodeFile = "Misra2012-mapping-broad.csv"

    if result != 0:
        print ("Error pulling the Misra mapping file")
        print (commandstr)
        sys.exit(1)

    if not os.path.isfile("warnings.sarif"):
        print ("File not found: warnings.sarif")
        sys.exit(1) 

    if not os.path.isfile(transcodeFile):
        print ("File not found: "+transcodeFile)
        sys.exit(1)

    # Read in the csv file
    with open(transcodeFile, "r") as csv_file:
        csv_reader = csv.reader(csv_file)
        next(csv_reader)
        mapping = list(csv_reader)  
    #    print (mapping[0][0] + "-" + mapping[0][8])



    # Read in the SARIF file and print to outfile
    outFile = open("warnings-MISRA.sarif", "w")
    with open("warnings.sarif", "r") as sarif_file:
        for line in sarif_file:
            for i in range(len(mapping)):
                if (mapping[i][8] in line):
                    line = line.replace(mapping[i][8], mapping[i][0] + "-" + mapping[i][8])
            outFile.write (line)

    outFile.close()

if CWE:
    # this is for the CWE mapping in the SARIF file if desired
    commandstr = os.getenv('CSONAR_CSHOME') + "/codesonar/bin/codesonar get   -auth password -hubuser " + \
        os.getenv('CSONAR_HUB_USER') + " -hubpwfile " + CSONAR_HUB_PW_FILE + " " + \
        "https://partnerdemo.codesonar.com/install/codesonar/doc/html/WarningClasses/CWE-mapping.csv"
    result=os.system(commandstr)
    transcodeFile = "CWE-mapping.csv"

    sarifFile = "warnings.sarif"

    if os.path.isfile("warnings-MISRA.sarif"):
        sarifFile = "warnings-MISRA.sarif"

    if not os.path.isfile(sarifFile):
        print ("File not found: " + sarifFile)
        sys.exit(1) 

    if not os.path.isfile(transcodeFile):
        print ("File not found: "+transcodeFile)
        sys.exit(1)

    # Read in the csv file
    with open(transcodeFile, "r") as csv_file:
        csv_reader = csv.reader(csv_file)
        next(csv_reader)
        mapping = list(csv_reader)  
    #    print (mapping[0][0] + "-" + mapping[0][8])



    # Read in the SARIF file and print to outfile
    outFile = open("warnings-CWE.sarif", "w")
    with open(sarifFile, "r") as sarif_file:
        for line in sarif_file:
            for i in range(len(mapping)):
                if (mapping[i][5] in line):
                    line = line.replace(mapping[i][5], mapping[i][0] + "-" + mapping[i][5])
            outFile.write (line)

    outFile.close()

#Finally, rename the files as needed
if CWE:
    os.rename("warnings-CWE.sarif", "warnings-translate.sarif")

if MISRA and not CWE:
    os.rename("warnings-MISRA.sarif", "warnings-translate.sarif")


#Last step: generate the json that GitLab wants
if GitLab:
        commandstr = os.getenv('CSONAR_CSHOME') + "/codesonar/bin/cspython /opt/codesonar-gitlab/codesonar-sarif2sast/sarif2sast.py --sarif warnings.sarif --output gl-sast-report.json " + \
           "--codesonar-url " + os.getenv("CSONAR_HUB_URL") + " --analysis-id " + str(current_project_aid)
        result=os.system(commandstr)
        print (commandstr)

        if result!= 0:
            print ("Error converting SARIF file to GitLab json")
            print (commandstr)
            sys.exit(0)  #TODO: change to exit 1
       

# remove hub credentials
if not Debug:
    os.remove(CSONAR_HUB_PW_FILE)
