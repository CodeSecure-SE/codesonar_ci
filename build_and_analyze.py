# The intent of this script is to be used as a wrapper for the CodeSonar
# analyze command.  It will run the build and analyze commands and then parse the
# resulting output file to determine if there are any new issues.  If there
# are new issues, it will return a sarif file with the new findings.
# This script is intended to be used as part of a CI/CD pipeline.
# 
# This script and this GitLab CI-Component is provided as an example by CodeSecure, \
# users are recommended to fork this project and customize it.


import os
import subprocess
import sys
import urllib.parse
from datetime import datetime
import urllib.request, urllib.error
import csv
import requests
import re
import atexit
import platform
import argparse
from contextlib import contextmanager

@contextmanager
def open_hub_pw_file(filename, password):
    f = open(filename, "w")
    try:
        f.write(password)
        yield f
    finally:
        f.close()

@contextmanager
def open_log_file(filename):
    f = open(filename, "w")
    try:
        yield f
    finally:
        f.close()

@contextmanager
def open_sarif_file(filename):
    f = open(filename, "w")
    try:
        yield f
    finally:
        f.close()
        
@contextmanager
def open_result_file(filename):
    f = open(filename, "r")
    try:
        yield f
    finally:
        f.close()


@contextmanager
def open_csv_file(filename, mode="r"):
    f = open(filename, mode, newline='')
    try:
        yield f
    finally:
        f.close()

@contextmanager
def open_sarif_read_file(filename):
    f = open(filename, "r")
    try:
        yield f
    finally:
        f.close()

@contextmanager
def open_sarif_write_file(filename):
    f = open(filename, "w")
    try:
        yield f
    finally:
        f.close()

CWE = False
MISRA = False
GitLab = False
GitHub = False

transcodeFile = ""

def cleanUp():
    if os.path.exists("hub_pw"):
        os.remove("hub_pw")


atexit.register(cleanUp)

def check_tree_existence(tree):
    tree_parts = tree.split('/')
    tree_parts.pop()
    current_tree = ""
    parent = 1
    result = None
    for part in tree_parts:
        print("Analyzing part: " + part)
        if current_tree=="":
            current_tree += "/"

            
        current_tree += part
            
        headers = {}
        auth = (os.getenv('CSONAR_HUB_USER'), os.getenv('CSONAR_HUB_PASSWORD'))
        url = f"{os.getenv('CSONAR_HUB_URL')}/projecttree/{str(parent)}.csv"
        print("Checking tree: " + url)
        response = requests.get(url, auth=auth, headers=headers, timeout=10)
        if response.status_code != 200:
            print(f"Error: {response.status_code} - {response.text}")
            exit(1)
        if ("Permission Denied" in response.text):
            print ("Permission denied, check username and password: " + current_tree)
            exit (1)
        csv_reader = csv.DictReader(response.text.splitlines(), delimiter=',')
        
        if 'name' not in csv_reader.fieldnames:
            print("Error: Missing 'name' column in CSV header.")
            print(csv_reader.fieldnames)
            print(response.text)
            sys.exit(1)
        
        found = False
        for row in csv_reader:
            if row['name'] == part:
                found = True 
                url = row['url']
                parent = re.search(r'/(\d+)\.csv$', url).group(1)           
        
        if (not found):
            print ("Creating project tree: " + part + " in parent: " + str(parent))
            url = os.getenv('CSONAR_HUB_URL') + "/projecttree/" + str(parent) + ".csv"
            data = {"new_ptree_name": part}
            print("Creating tree: " + url)

            try:
                response = requests.post(
                    url,
                    auth=(os.getenv('CSONAR_HUB_USER'), os.getenv('CSONAR_HUB_PASSWORD')),
                    data=data, timeout=10
                )
                if response.status_code != 200:
                    print("Problem creating tree: " + current_tree)
                    print(f"Error: {response.status_code} - {response.text}")
                    exit(1)
                result_output = response.text
            except Exception as e:
                print("Problem creating tree: " + current_tree)
                print(f"Exception: {e}")
                exit(1)

            if ("Not Found" in result_output):
                print ("Tree not found: " + current_tree)
                print ("Error: " + result_output)
                exit (1)
            if ("Permission Denied" in result_output):
                print ("Permission denied, check username and password: " + current_tree)
                exit (1)

            csv_reader = csv.DictReader(result_output.splitlines(), delimiter=',')

            for row in csv_reader:
                if row['name'] == part:
                    found = True 
                    url = row['url']
                    parent = re.search(r'/(\d+)\.csv$', url).group(1)
            

                

def main():
    global CWE, MISRA, GitLab, GitHub, transcodeFile

    # Now you can read and assign to these variables inside main()
    CWE = True
    MISRA = False
    

    # first check if we have all the required arguments

    print("CodeSonar Build and Analyze Script")
    

    parser = argparse.ArgumentParser(description="Wrapper for CodeSonar analyze command.")
    parser.add_argument('conf_file', help='Path to the configuration file')
    parser.add_argument('build_command', nargs=argparse.REMAINDER, help='Build command and its arguments')
    parser.add_argument('-cwe', action='store_true', help='Add the CWE id to the warning class name in the SARIF file')
    parser.add_argument('-misra', action='store_true', help='Add the MISRA classes to the warning class name in the SARIF file')
    parser.add_argument('-preset', type=str, help='Specify a preset to use')
    parser.add_argument('-noupload', action='store_true', help='Do not upload remote archive')

    args = parser.parse_args()

    if not args.conf_file:
        print("Insufficient parameters, exiting")
        print("Usage: build_and_analyze.py [options] <conf-file> <build-command>")
        print("Script outputs:")
        print("  - warnings.sarif: SARIF file with the warnings in PR (if triggered by a PR), or all visible warnings")
        print("  - warnings.md: Markdown related to the above")
        sys.exit(1)

    CWE = args.cwe
    MISRA = args.misra
    preset = f"-preset {args.preset}" if args.preset else ""
    uploadFlag = '' if args.noupload else '-remote-archive /analyze/*'
    conf_file = args.conf_file
    build_command = args.build_command

    all_ok=True

    def check_env(s, t):
        global all_ok
        if os.getenv(s) is None:
            print("Missing " + s + " environment variable, should be set to " + t)
            all_ok=False   

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
            # Note: This is a simplification and will need modification for merges to non-default branches
        if os.getenv("COMMIT_HASH") is None:
            os.environ['COMMIT_HASH'] = os.getenv('CI_COMMIT_SHA', "None")
        if os.getenv("TOKEN") is None:
            os.environ['TOKEN'] = os.getenv('CI_JOB_TOKEN', "None")

    # checking environment variables
    check_env('CSONAR_HUB_URL', 'URL for CodeSonar HUB') 
    os.environ['CSONAR_HUB_URL'] = os.getenv('CSONAR_HUB_URL').rstrip('/')

    check_env('CSONAR_HUB_USER', 'Username for CodeSonar HUB')
    check_env('CSONAR_HUB_PASSWORD', 'Password for CodeSonar HUB')
    check_env('CSONAR_CSHOME', 'Path to CodeSonar installation')
    check_env('ROOT_TREE', 'Path to the project-tree in the CodeSonar HUB')
    check_env('PROJECT_NAME', 'Name of the project in the CodeSonar HUB')
    check_env('TOKEN', 'Token API')
    check_env('REPO_URL', 'URL for repository')
    check_env('REQUEST_NUMBER', 'Pull/Merge request ID')
    check_env('BRANCH_NAME', 'Name of the current branch ')
    check_env('IS_PR', 'Set to true if this is a pull/merge request')
    check_env('TARGET', 'Target branch for the pull/merge request')
    check_env("COMMIT_HASH", "Commit hash")


    if not all_ok:
        print("Exiting, not all variables have been set!")
        sys.exit(1)

    # create hub credentials
    CSONAR_HUB_PW_FILE = "hub_pw"
    with open_hub_pw_file(CSONAR_HUB_PW_FILE, os.getenv('CSONAR_HUB_PASSWORD')):
        pass

    target_project_aid = 0
    codesonar_command = os.path.join(os.getenv('CSONAR_CSHOME'), "codesonar", "bin", "codesonar")
    cspython_command = os.path.join(os.getenv("CSONAR_CSHOME"), "codesonar", "bin", "cspython")


    if platform.system() == 'Windows':
        ampersand = "^&"
    else:
        ampersand = "&"
    
    # If this is a PR/MR, find the analysis-id of the latest analysis on the target branch
    if os.getenv('IS_PR') != 'None':
        
        link = "{\"limit\":1,\"orderBy\":[{\"analysisId\":\"DESCENDING\"}],\"columns\":[\"analysisId\"]}"
        query = "\"branch_name\"=\"" + os.getenv("TARGET") + "\"state=\"Finished\""

        command = [
            codesonar_command,
            "get",
            "-auth", "password",
            "-hubuser", os.getenv('CSONAR_HUB_USER'),
            "-hubpwfile", CSONAR_HUB_PW_FILE,
            f"{os.getenv('CSONAR_HUB_URL')}/analysis_search.csv?sanlgrid_json={urllib.parse.quote(link)}{ampersand}query={urllib.parse.quote(query)}",
            "-o", "-"
        ]

        try:
            print ("Running: " + " ".join(command))
            result = subprocess.run(command, shell=False, capture_output=True, text=True)
            
            if len(result.stdout.splitlines()) < 2:
                print ("No existing analysis found, continuing")
                target_project_aid = "0"
            else: 
                target_project_aid = result.stdout.splitlines()[1]
        except subprocess.CalledProcessError as e:
            print(f"Error retrieving analysis id: {' '.join(command)}")
            print(f"Error details: {e.stderr}")
            sys.exit(1)

    namestr = datetime.now().strftime("%m/%d/%Y-%H:%M:%S")

    # Test if the project tree exists
    print ("Checking project tree")
    check_tree_existence(os.getenv("ROOT_TREE")+"/"+os.getenv("BRANCH_NAME"))
    


    cmd = [
        codesonar_command,
        "build",
        os.getenv("PROJECT_NAME")]

    if uploadFlag:
        cmd.extend(uploadFlag.split())

    if preset:
        cmd.extend(preset.split())

    cmd.extend([
        "-foreground",
        "-auth","password",
        "-hubuser", os.getenv('CSONAR_HUB_USER'),
        "-hubpwfile", CSONAR_HUB_PW_FILE,
        "-project", os.getenv("ROOT_TREE") + "/" + os.getenv("BRANCH_NAME"),
        "-name", namestr,
        "-conf-file", conf_file,
        os.getenv("CSONAR_HUB_URL")
    ])
    cmd.extend(build_command)


    result =   subprocess.run(cmd, shell=False, capture_output=False, text=True)

    if result.returncode != 0:
        print (f"Problem ({result.returncode}) running build command: " + str(cmd))
        sys.exit(1)   


    #Construct the properties, these are stored on the analysis and provide a link from CodeSonar to GitLab

    property_job_link = os.getenv('CI_JOB_URL') 


    with open_result_file(os.path.join(os.getenv("PROJECT_NAME")+".prj_files","aid.txt")) as f:
        current_project_aid = f.read()


    if os.getenv('IS_PR') != "None":
        property_new_findings = os.getenv('CSONAR_HUB_URL') +"/search.html?query=" + \
            urllib.parse.quote("aid:"+str(current_project_aid) + " DIFFERENCE aid:" + str(target_project_aid)) + \
             "&scope=" + urllib.parse.quote("aid:" + str(current_project_aid)) + "&swarnings=BJAW"
    else:
        property_new_findings = "Not available"

    property_commit_link = os.getenv('REPO_URL') + "/commit/" + os.getenv('COMMIT_HASH')


    if os.getenv('TARGET') == "":
        targetStr="None"
    else: 
        targetStr=os.getenv('TARGET')



    # Build analyze command arguments
    analyze_cmd = [
        codesonar_command,
        "analyze",
        os.getenv("PROJECT_NAME")
    ]

    if uploadFlag:
        analyze_cmd.extend(uploadFlag.split())

    analyze_cmd.extend([
        "-foreground",
        "-auth", "password",
        "-hubuser", os.getenv('CSONAR_HUB_USER'),
        "-hubpwfile", CSONAR_HUB_PW_FILE,
        "-project", f"{os.getenv('ROOT_TREE')}/{os.getenv('BRANCH_NAME')}",
        "-property", "new_findings", property_new_findings,
        "-property", "target_branch" ,targetStr,
        "-property", "commit_link", property_commit_link,
        "-property", "branch_name", os.getenv('BRANCH_NAME'),
        "-name", namestr,
        "-conf-file", conf_file,
        os.getenv("CSONAR_HUB_URL")
    ])

    print(f"Running analyze command: {' '.join(analyze_cmd)}")

    try:
        result = subprocess.run(
            analyze_cmd,
            shell=False,
            capture_output=True,
            text=True
        )
        
        # Write output to analysis.log
        with open_log_file("analysis.log") as log_file:
            log_file.write(result.stdout)
            log_file.write(result.stderr)
        
        if result.returncode != 0:
            print("Problem running analyze command")
            print("stdout:", result.stdout)
            print("stderr:", result.stderr)
            sys.exit(1)

    except subprocess.CalledProcessError as e:
        print(f"Error running analyze command: {e}")
        print(f"Error details: {e.stderr}")
        sys.exit(1)
        

    # Download the new findings results in SARIF, if it is a merge/pull request
    if os.getenv('IS_PR') == 'pull_request' or os.getenv('IS_PR') == 'merge_request_event':
        # Pull just the changes
        print ("Running in a Merge Request/Pull Request, pulling only the new warnings.")
        # Build command to get warning details in SARIF format
        # Note that we are using codesonar get here and not dump_warnings. 
        # dump_warnings cannot to the difference search that we want
        warning_cmd = [
            codesonar_command,
            "get",
            "-auth", "password", 
            "-hubuser", os.getenv('CSONAR_HUB_USER'),
            "-hubpwfile", CSONAR_HUB_PW_FILE,
            f"{os.getenv('CSONAR_HUB_URL')}/warning_detail_search.sarif"
            f"?filter=%22active%20not%20clustered%22&"
            f"query={urllib.parse.quote(f'aid:{current_project_aid} DIFFERENCE aid:{target_project_aid}')}"
            f"{ampersand}scope={urllib.parse.quote(f'aid:{current_project_aid}')}"
            f"{ampersand}swarnings=BJAW",
            "-o", "-"
        ]
        

        try:
            result = subprocess.run(
                warning_cmd,
                shell=False,
                capture_output=True,
                text=True
            )
            
            # Write output to warnings.sarif
            with open_sarif_write_file("warnings.sarif") as sarif_file:
                sarif_file.write(result.stdout)
            
            if result.returncode != 0:
                print("Error retrieving SARIF file")
                print("stdout:", result.stdout)
                print("stderr:", result.stderr)
                sys.exit(1)
        
        except subprocess.CalledProcessError as e:
            print(f"Error retrieving SARIF file: {e}")
            print(f"Error details: {e.stderr}")
            sys.exit(1)

    
    else:
        print ("No Merge Request/Pull Request detected, pulling All Warnings.")
        # Pull everything as a summary
        dump_warnings_cmd = [
            codesonar_command,
            "dump_warnings.py",
            "-auth", "password",
            "-hubuser", os.getenv('CSONAR_HUB_USER'),
            "-hubpwfile", CSONAR_HUB_PW_FILE,
            "--hub", os.getenv('CSONAR_HUB_URL'),
            "--project-file", f"{os.getenv('PROJECT_NAME')}.prj",
            "--visible-warnings", "active not clustered",
            "--sarif",
            "-o", "warnings.sarif"
        ]
        
        try:
            result = subprocess.run(
                dump_warnings_cmd,
                shell=False,
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                print("Error pulling data from HUB")
                print("Command:", " ".join(dump_warnings_cmd))
                print("stderr:", result.stderr)
                sys.exit(1)
        
        except subprocess.CalledProcessError as e:
            print(f"Error pulling data from HUB: {e}")
            print(f"Error details: {e.stderr}")
            sys.exit(1)
                



    # Last thing to do is to add CWE or MISRA namings into the SARIF file
    if MISRA:
        # this is for the MISRA mapping in the SARIF file if desired
        # Pull everything as a summary
        misra_mapping_cmd = [
            codesonar_command,
            "get",
            "-auth", "password",
            "-hubuser", os.getenv('CSONAR_HUB_USER'),
            "-hubpwfile", CSONAR_HUB_PW_FILE,
            f"{os.getenv('CSONAR_HUB_URL')}/install/codesonar/doc/html/WarningClasses/MisraC2023-mapping-broad.csv"
        ]
        
        try:
            result = subprocess.run(
                misra_mapping_cmd,
                shell=False,
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                print("Error pulling data from HUB")
                print("Command:", " ".join(misra_mapping_cmd))
                print("stderr:", result.stderr)
                sys.exit(1)
        
        except subprocess.CalledProcessError as e:
            print(f"Error pulling data from HUB: {e}")
            print(f"Error details: {e.stderr}")
            sys.exit(1)

        transcodeFile = "MisraC2023-mapping-broad.csv"
        # Read in the csv file
        with open_csv_file(transcodeFile) as csvfile:
            csv_reader = csv.DictReader(csvfile)
            with open_sarif_write_file("warnings-MISRA.sarif") as outFile:
                with open_sarif_read_file("warnings.sarif") as sarif_file:
                    for line in sarif_file:
                        for row in csv_reader:
                            if (row['CodeSonar Class Name'] in line):
                                line = line.replace(row['CodeSonar Class Name'], row['CodeSonar Class Name']+ " - " + row['Category ID']  )
                        outFile.write(line)

        
    if CWE:
        # Build command to get CWE mapping file
        cwe_mapping_cmd = [
            codesonar_command,
            "get",
            "-auth", "password",
            "-hubuser", os.getenv('CSONAR_HUB_USER'),
            "-hubpwfile", CSONAR_HUB_PW_FILE,
            f"{os.getenv('CSONAR_HUB_URL')}/install/codesonar/doc/html/WarningClasses/CWE-mapping.csv"
        ]

        try:
            result = subprocess.run(
                cwe_mapping_cmd,
                shell=False,
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                print("Error retrieving CWE mapping file")
                print("stdout:", result.stdout)
                print("stderr:", result.stderr)
                sys.exit(1)

        except subprocess.CalledProcessError as e:
            print(f"Error retrieving CWE mapping file: {e}")
            print(f"Error details: {e.stderr}")
            sys.exit(1)
        
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
        with open_csv_file(transcodeFile) as csv_file:
            csv_reader = csv.reader(csv_file)
            next(csv_reader)
            mapping = list(csv_reader)
        # Read in the SARIF file and print to outfile
        with open_sarif_write_file("warnings-CWE.sarif") as outFile:
            with open_sarif_read_file(sarifFile) as sarif_file:
                for line in sarif_file:
                    for i in range(len(mapping)):
                        if (mapping[i][5] in line):
                            line = line.replace(mapping[i][5], mapping[i][0] + "-" + mapping[i][5])
                    outFile.write(line)

    #Finally, rename the files as needed
    if CWE:
        if os.path.isfile("warnings.sarif"):
            os.remove("warnings.sarif")
        os.rename("warnings-CWE.sarif", "warnings.sarif")

    if MISRA and not CWE:
        if os.path.isfile("warnings.sarif"):
            os.remove("warnings.sarif")
        os.rename("warnings-MISRA.sarif", "warnings.sarif")


    #Last step: generate the json that GitLab wants
    if GitLab:

        # Build command to convert SARIF to GitLab SAST format
        sarif_to_sast_cmd = [
            cspython_command,
            os.path.join(os.getenv("CSONAR_CSHOME"), "third-party", "codesonar-sarif2sast", "sarif2sast.py"),
            "--sarif", "warnings.sarif",
            "--output", "gl-sast-report.json",
            "--summary-report", "warnings.md",
            "--codesonar-url", os.getenv("CSONAR_HUB_URL"),
            "--analysis-id", str(current_project_aid)
        ]
        try:
            result = subprocess.run(
                sarif_to_sast_cmd,
                shell=False,
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                print("Error converting SARIF file to GitLab json")
                print("Command:", " ".join(sarif_to_sast_cmd))
                print("stderr:", result.stderr)
                sys.exit(1)

        except subprocess.CalledProcessError as e:
            print(f"Error converting SARIF file to GitLab json: {e}")
            print(f"Error details: {e.stderr}")
            sys.exit(1)

if __name__ == "__main__":
    main()