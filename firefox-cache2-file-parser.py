import argparse
import os
import struct
import datetime
import hashlib
import csv
import sys

argParser = argparse.ArgumentParser(description='Parse Firefox cache2 files in a directory or individually.')
argParser.add_argument('-d', '--directory', help='directory with cache2 files to parse', required=True)
argParser.add_argument('-f', '--file', help='single cache2 file to parse')
argParser.add_argument('-o', '--output', help='CSV output file')
args = argParser.parse_args()


chunkSize = 256 * 1024

skippedFiles = []

def UnpackCache2Field (parseFile, format, bytes, field):
    try:
        return struct.unpack(format, parseFile.read(bytes))[0]
    except struct.error as e:
        print "Error unpacking cache2 field {0}: {1}".format(field, e)
        skippedFiles.append(parseFile.name)
        return None
    

def ParseCacheFile (parseFile):
    print "parsing file: {0}".format(parseFile.name)
    try: 
        fileSize = os.path.getsize(parseFile.name)
        parseFile.seek(-4, os.SEEK_END)
        #print parseFile.tell()
        #print fileSize
        #metaStart = struct.unpack('>I', parseFile.read(4))[0]
        metaStart = UnpackCache2Field(parseFile, '>I', 4, 'metadata-start')
        if metaStart is None:
            print "Skipping file..."
            return
            
        #print metaStart
        numHashChunks = metaStart / chunkSize
        if metaStart % chunkSize :
            numHashChunks += 1
        #print 4 + numHashChunks * 2
        parseFile.seek(metaStart + 4 + numHashChunks * 2, os.SEEK_SET)
        #print parseFile.tell()

        #version = struct.unpack('>I', parseFile.read(4))[0]
        version = UnpackCache2Field(parseFile, '>I', 4, 'version')
        if version is None:
            print "Skipping file..."
            return
        #if version > 1 :
            # TODO quit with error
        #fetchCount = struct.unpack('>I', parseFile.read(4))[0]
        fetchCount = UnpackCache2Field(parseFile, '>I', 4, 'fetchCount')
        if fetchCount is None:
            print "Skipping file..."
            return
        #lastFetchInt = struct.unpack('>I', parseFile.read(4))[0]
        lastFetchInt = UnpackCache2Field(parseFile, '>I', 4, 'lastFetchInt')
        if lastFetchInt is None:
            print "Skipping file..."
            return
        #lastModInt = struct.unpack('>I', parseFile.read(4))[0]
        lastModInt = UnpackCache2Field(parseFile, '>I', 4, 'lastModInt')
        if lastModInt is None:
            print "Skipping file..."
            return
        #frecency = struct.unpack('>I', parseFile.read(4))[0]
        frecency = UnpackCache2Field(parseFile, '>I', 4, 'frecency')
        if frecency is None:
            print "Skipping file..."
            return
        #expireInt = struct.unpack('>I', parseFile.read(4))[0]
        expireInt = UnpackCache2Field(parseFile, '>I', 4, 'expireInt')
        if expireInt is None:
            print "Skipping file..."
            return
        keySize = struct.unpack('>I', parseFile.read(4))[0]
        keySize = UnpackCache2Field(parseFile, '>I', 4, 'keySize')
        if keySize is None:
            print "Skipping file..."
            return
        #flags = struct.unpack('>I', parseFile.read(4))[0] if version >= 2 else 0
        flags = UnpackCache2Field(parseFile, '>I', 4, 'flags') if version >= 2 else 0
        if flags is None:
            print "Skipping file..."
            return
            
        key = parseFile.read(keySize)
        key_hash = hashlib.sha1(key).hexdigest().upper()

        if doCsv :
            csvWriter.writerow((fetchCount,
                                datetime.datetime.fromtimestamp(lastFetchInt),
                                datetime.datetime.fromtimestamp(lastModInt),
                                hex(frecency),
                                datetime.datetime.fromtimestamp(expireInt),
                                flags,
                                key,
                                key_hash))

        print "version: {0}".format(version)
        print "fetchCount: {0}".format(fetchCount)
        print "lastFetch: {0}".format(datetime.datetime.fromtimestamp(lastFetchInt))
        print "lastMod: {0}".format(datetime.datetime.fromtimestamp(lastModInt))
        print "frequency: {0}".format(hex(frecency))
        print "expire: {0}".format(datetime.datetime.fromtimestamp(expireInt))
        print "keySize: {0}".format(keySize)
        print "flags: {0}".format(flags)
        print "key: {0}".format(key)
        print "key sha1: {0}\n".format(key_hash)
    
    except :
        print "Unexpected error:", sys.exc_info()[0]
    
#ParseCacheFile(testFile)
#procPath = script_dir + '/' + testDir

# Output to CSV
doCsv = args.output
if doCsv :
    # https://stackoverflow.com/questions/3348460/csv-file-written-with-python-has-blank-lines-between-each-row
    csvFile = open(args.output, 'wb')
    csvWriter = csv.writer(csvFile, delimiter=';', quoting=csv.QUOTE_NONNUMERIC)
    csvWriter.writerow(('Fetch Count', 'Last Fetch', 'Last Modified', 'Frecency', 'Expiration', 'Flags', 'URL', 'Key Hash'))

procPath = args.directory
# Only one file to process
if args.file :
    fileList = [args.file]
else :
    fileList = os.listdir(procPath)

for filePath in fileList :
    if os.path.isdir(filePath) :
        continue
    else :
        file = open(os.path.join(procPath, filePath), 'r')
        ParseCacheFile(file)
    
if doCsv :
    print 'Data written to CSV file: {0}'.format(csvFile.name)
    csvFile.close()

if skippedFiles:
    print "Skipped files:"
    print "\n".join(skippedFiles)
