import csv
import sys
import os.path


if (len(sys.argv) < 2):
    print("Insufficient parameters, exiting")
    print("Usage: CodeSecure_SAST_Score.py aid")
    print ("   This expects <aid>.csv and <aid>-files.csv to be in the current directory")
    sys.exit(1)




allFilePaths = []
allSignificance = []
completeFile = []

index = 0
warningsFile=sys.argv[1]+".csv"
locFile=sys.argv[1]+"-files.csv"

if (not os.path.isfile(warningsFile)):
    print ("File not found: "+warningsFile)
    sys.exit(1)

if (not os.path.isfile(locFile)):
    print ("File not found: "+locFile)
    sys.exit(1)

# With code from Alex Hermeling
significanceTypes = ["Security", "Reliability", "Redundancy", "Style"]

with open(warningsFile,"r") as csv_file:
    csv_reader = csv.reader(csv_file)
    for i in csv_reader:
        completeFile.append(i)
        allFilePaths.append(i[5])
        allSignificance.append(i[3])

    filePaths = list(set(allFilePaths))
    filePaths.remove("file path")
    
    
    def significanceNum(path, significance):
        count = 0
        for i in range(len(completeFile)):
            if completeFile[i][5] == path and completeFile[i][3] == significance:
                count += 1
        return count

    allTempSig = []
    filePathAndSig = []
    for i in range(len(filePaths)):
        for j in range(len(significanceTypes)):
            TempSig = [significanceTypes[j], significanceNum(filePaths[i],significanceTypes[j])]
            allTempSig.append(TempSig)
        filePathAndSig.append([filePaths[i], list(allTempSig)])
        allTempSig.clear()

totals = [0,0,0,0,0,0]


for i in range(len(filePathAndSig)):
    for j in range(len(significanceTypes)):
        totals[j] += filePathAndSig[i][1][j][1]


csv_file.close()

locCount = {}
totalLoc = 0
with open(locFile,"r") as loc_file:
    loc_reader = csv.reader(loc_file)
    next (loc_reader)
    for row in loc_reader:
        locCount[row[0]] = int(row[2])
        totalLoc += int(row[2])


print("\n\n#CodeSecure SAST Score\n")
for i in range(len(significanceTypes)):
    print("**"+significanceTypes[i] + "**: {:.1f}".format(totals[i]/(totalLoc/1000)))

print("\n\nTotal warnings: " + str(len(completeFile)-1))
print( "Lines of code:  " + str(totalLoc) )