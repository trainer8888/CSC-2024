from zipfile import ZipFile
import os

with open('Matryoshka dolls.jpg', 'rb') as f:
    hexbytes = f.read()
    # JPEG image files begin with FF D8 and end with FF D9.
    # find the index after ff and d9
    start = 0
    for i in range(len(hexbytes)-1):
        if hexbytes[i] == int('ff', 16) and hexbytes[i+1] == int('d9', 16):
            start = i + 2
            break
    # write the additional bytes to a file
    output = open('answer', 'wb')
    for i in range(start, len(hexbytes)):
        output.write(bytes([hexbytes[i]]))
    output.close()
    # we know answer is a zip file and flag.txt is png through human eye 
    # we can use file command to check the file type, too.
    with ZipFile('answer', 'r') as fd:
        fd.extractall('./')
    os.system("rm answer")
    os.rename('flag.txt', 'flag.png')