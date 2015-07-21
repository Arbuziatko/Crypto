import sys

def shiftDataByKey(data,shift):
		shiftedData = ""
		for i in range(len(data)):
			index = base64Alphabet.find(data[i])
			if index != -1:
				shiftedIndex = index - shift
				shiftedData += base64Alphabet[shiftedIndex]
			else:
				shiftedData += data[i]
		return shiftedData


base64Alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


if __name__ == "__main__":
	fin = open(sys.argv[-1],'r')
	fout = open("decodedResulsts.txt",'w')
	data = fin.read().replace('\n','')
	
	for shift in range(64):
		fout.write("Shift %i : " % shift)
		fout.write(shiftDataByKey(data, shift))
		# fout.write(shiftedData.decode("base64"))
		fout.write("\n")