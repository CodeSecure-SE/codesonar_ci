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
def open_log_file(filename):
    f = open(filename, "w")
    try:
        yield f
    finally:
        f.close()

GitLab = False
GitHub = False





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
    # first check if we have all the required arguments

    print("CodeSonar Build and Analyze Script")
    

    parser = argparse.ArgumentParser(description="Wrapper for CodeSonar analyze command.")
    parser.add_argument('conf_file', help='Path to the configuration file')
    parser.add_argument('build_command', nargs=argparse.REMAINDER, help='Build command and its arguments')
    parser.add_argument('-conf_insert', type=str, help='Specify a configuration insert text to use')
    parser.add_argument('-noupload', action='store_true', help='Do not upload remote archive')

    args = parser.parse_args()

    if not args.conf_file:
        print("Insufficient parameters, exiting")
        print("Usage: build_and_analyze.py [options] <conf-file> <build-command>")
        print("Script outputs:")
        print("  - warnings.sarif: SARIF file with the warnings in PR (if triggered by a PR), or all visible warnings")
        print("  - warnings.md: Markdown related to the above")
        sys.exit(1)

 

    conf_file = args.conf_file
    build_command = args.build_command

    all_ok=True

    def check_env(s, t):
        global all_ok
        if os.getenv(s) is None:
            print("Missing " + s + " environment variable, should be set to " + t)
            all_ok=False   

    
    # checking environment variables, CSONAR is the -cs-environment-format
    check_env('CSONAR_HUB_URL', 'URL for CodeSonar HUB') 
    os.environ['CSONAR_HUB_URL'] = os.getenv('CSONAR_HUB_URL').rstrip('/')

    check_env('CSONAR_HUB_USER', 'Username for CodeSonar HUB')
    check_env('CSONAR_HUB_PASSWORD', 'Password for CodeSonar HUB')
    check_env('CSONAR_CSHOME', 'Path to CodeSonar installation')
    check_env('ROOT_TREE', 'Path to the project-tree in the CodeSonar HUB')
    check_env('PROJECT_NAME', 'Name of the project in the CodeSonar HUB')
    
    check_env('REPO_URL', 'URL for repository')
    check_env('REQUEST_NUMBER', 'Pull/Merge request ID')
    check_env('BRANCH_NAME', 'Name of the current branch ')
    check_env('TARGET', 'Target branch for the pull/merge request')
    


    if not all_ok:
        print("Exiting, not all variables have been set!")
        sys.exit(1)


    codesonar_command = os.path.join(os.getenv('CSONAR_CSHOME'), "codesonar", "bin", "codesonar")
    cspython_command = os.path.join(os.getenv("CSONAR_CSHOME"), "codesonar", "bin", "cspython")
    citool_command = os.path.join(os.getenv("CSONAR_CSHOME"), "csonar-ci", "py", "tools", "codesonar_citool.py")
    codesonar_options = ["-conf-file", conf_file, args.conf_insert]
    citool_global_options = ["-use-environment"]
    citool_search_options = ["-comparison-analysis", "?(branch=\"" + os.getenv("TARGET") + "\" state=\"finished\")"] # Need to understand how to do this if no TARGET]
    citool_check_options = ["-dump-sarif", "warnings.sarif", "-summary", "warnings.md"]

    if platform.system() == 'Windows':
        ampersand = "^&"
    else:
        ampersand = "&"
    
    namestr = datetime.now().strftime("%m/%d/%Y-%H:%M:%S")

    # Test if the project tree exists, if not, create it
    print ("Checking project tree")
    check_tree_existence(os.getenv("ROOT_TREE")+"/"+os.getenv("BRANCH_NAME"))
    
    # We want to run codesonar_citool.py to abstract our handling using the environment
    # But we need to translate the environment variables to what it is expecting, the env_var names used in many of 
    # the projects we have are slightly different.
    os.environ["CODESONAR_HUBUSER"] = os.getenv("CSONAR_HUB_USER")
    os.environ["CODESONAR_HUBPWVAL"] = os.getenv("CSONAR_HUB_PASSWORD")
    os.environ["CODESONAR_PROJECT_PATH"] = os.getenv("ROOT_TREE") + "/" + os.getenv("BRANCH_NAME")

    properties = ["-property", "branch_name", os.getenv('BRANCH_NAME'), 
                  "-property", "target_branch", os.getenv('TARGET')]
    
    if not args.noupload:
        os.environ["CODESONAR_REMOTE_ARCHIVE"] = "/saas/*"

    cmd = [
        cspython_command,
        citool_command,
        os.getenv("PROJECT_NAME"),
        citool_global_options,
        codesonar_options,
        properties,
        citool_search_options,
        citool_check_options,
        os.getenv("CSONAR_HUB_URL"),
        build_command]

    result =   subprocess.run(cmd, shell=False, capture_output=True, text=True)


    # Write output to analysis.log
    with open_log_file("analysis.log") as log_file:
        log_file.write(result.stdout)
        log_file.write(result.stderr)
    
    if result.returncode != 0:
        print("Problem running analyze command")
        print("stdout:", result.stdout)
        print("stderr:", result.stderr)
        sys.exit(1)
   

if __name__ == "__main__":
    main()