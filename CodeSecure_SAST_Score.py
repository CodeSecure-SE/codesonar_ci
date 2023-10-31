import csv


if (len(sys.argv) < 2):
    print("Insufficient parameters, exiting")
    print("Usage: CodeSecure_SAST_Score.py <csv-file>")
    sys.exit(1)
csv_file = sys.argv[1]



allFilePaths = []
allSignificance = []
completeFile = []

index = 0

# With code from Alex Hermeling

with open(csv-file,"r") as csv_file:
    csv_reader = csv.reader(csv_file)
    for i in csv_reader:
        completeFile.append(i)
        allFilePaths.append(i[5])
        allSignificance.append(i[3])

    filePaths = list(set(allFilePaths))
    filePaths.remove("file path")
    significanceTypes = list(set(allSignificance))
    significanceTypes.remove("significance")
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
    print(filePathAndSig)