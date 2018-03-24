#!/usr/bin/python2

import os 
import numpy as np
import matplotlib.pyplot as plt
import statistics

OFFSET_HEADER = 4
NUMBER_OF_CIPHERS = 22

def parse_logs(dname):

	xlabels_set = False
	xlabels = []

	raw = [[] for _ in range(NUMBER_OF_CIPHERS)]
	encrypted = [[] for _ in range(NUMBER_OF_CIPHERS)]
	speed = [[] for _ in range(NUMBER_OF_CIPHERS)]
	nonchannel = [[] for _ in range(NUMBER_OF_CIPHERS)]

	for file in os.listdir(dname):
		if file.endswith(".log"):
			with open(os.path.join(dname, file), 'r') as f:
				log = f.read().split('\n')
				for i in range(OFFSET_HEADER, len(log)-1, 5):
					if not xlabels_set:
						xlabels.append(log[i])

					index = xlabels.index(log[i])
					raw[index].append(log[i+1].replace(' ', '').split(':')[1])
					encrypted[index].append(log[i+2].replace(' ', '').split(':')[1])
					speed[index].append(log[i+3].rstrip().replace(' ', '').split(':')[1])
					nonchannel[index].append(log[i+4].rstrip().replace(' ', '').split(':')[1])

				xlabels_set = True	

	return xlabels, raw, encrypted, speed, nonchannel

if __name__ == '__main__':

	# More samples
	# Look at minimum
	
	#xlabels, raw, encrypted, speed = parse_logs("logs/laptop-rhul-to-aws-london")
	#xlabels, raw, encrypted, speed = parse_logs("logs/aws-london-to-aws-us-west-oregon")
	#xlabels, raw, encrypted, speed, nonchannel = parse_logs("logs/dl-aws-london-to-aws-us-west-oregon")
	#xlabels, raw, encrypted, speed = parse_logs("logs/ul-aws-london-to-aws-us-west-oregon")	
	xlabels, raw, encrypted, speed, nonchannel = parse_logs("logs/ul-aws-london-to-aws-us-oregon")

	file_size = 100

	lmb = []
	MB = 0.000001

	rawmedian = []
	rawvariance = [] 
	for l in raw:
		lmb = [ x * MB for x in map(int,l)]
		rawmedian.append(np.median(lmb))
		rawvariance.append(np.var(lmb))

	encryptedmedian = []
	encryptedvariance = []
	for i, l in enumerate(encrypted):
		lmb = [ x * MB for x in map(int,l)]
		encryptedmedian.append(np.median(lmb))
		encryptedvariance.append(np.var(lmb))

	speedmedian = []
	speedvariance = []
	for i, l in enumerate(speed):
		lmb = [ (100 / x) for x in map(float,l)]
		speedmedian.append(np.median(lmb))
		speedvariance.append(np.var(lmb))

	nonchannelmedian = []
	nonchannelvariance = []
	for i, l in enumerate(nonchannel):
		lmb = [ x * MB for x in map(int,l)]
		nonchannelmedian.append(np.median(lmb))
		nonchannelvariance.append(np.var(lmb))

	#print rawvariance
	#print encryptedvariance
	#print speedvariance
	#print nonchannelvariance

	#rawmedian = [ x * MB for x in rawmedian]
	#rawvariance = [ x * MB for x in rawvariance]	
	#encryptedmedian = [ x * MB for x in encryptedmedian]
	#encryptedvariance = [ x * MB for x in encryptedvariance]
	#speedmedian = [ x * MB for x in speedmedian]
	#speedvariance = [ x * MB for x in speedvariance]

	x = np.arange(NUMBER_OF_CIPHERS * 2, step=2)
	width = 1.2

	#fig, (ax1, ax2, ax3, ax4) = plt.subplots(ncols=4)
	fig, ax2 = plt.subplots(ncols=1)

	#rec1 = ax1.bar(x + 1, rawmedian, width, color='r')
	#ax1.errorbar(x +1, rawmedian, yerr=rawvariance, linestyle='None')
	#ax1.set_title("Total raw bytes")
	#ax1.set_ylabel("MB")

	rec2 = ax2.barh(x, speedmedian, align='center', color='r')
	#ax2.errorbar(x +1, encryptedmedian, encryptedvariance, linestyle='None')
	ax2.set_title("Throughput (100MB file)")
	ax2.set_xlabel("MB/s")
	plt.yticks(x, xlabels)

	#rec2 = ax2.bar(x + 1, encryptedmedian, width, color='r')
	#rec2 = ax2.barh(x, encryptedmedian, align='center', color='r')
	#ax2.errorbar(x +1, encryptedmedian, encryptedvariance, linestyle='None')
	#ax2.set_title("Total encrypted bytes")
	#ax2.set_xlabel("MB")
	plt.yticks(x, xlabels)

	#rec1 = ax1.bar(x + 1, speedmedian, width, color='r')
	#ax1.errorbar(x +1, speedmedian, speedvariance, linestyle='None')
	#ax1.set_title("Throughput (100MB file)")
	#ax1.set_ylabel("MB/s")
	#plt.xticks(x + (width / 2), xlabels, rotation=90, fontsize=10) # (position of x-labels, x-labels)

	#rec4 = ax4.bar(x + 1, nonchannelmedian, width, color='r')
	#ax3.errorbar(x +1, speedmedian, speedvariance, linestyle='None')
	#ax4.set_title("Total non channel bytes")

	def autolabel(rects, ax):
	    # Get y-axis height to calculate label position from.
	    (y_bottom, y_top) = ax.get_ylim()
	    i = 0
	    for rect in rects:
	        label_position = y_bottom + 5
	        ax.text(rect.get_x() + rect.get_width()/2 + 0.1, label_position,
	                xlabels[i],
	                ha='center', va='bottom', rotation=90, fontsize=10)
	        i = i + 1

	#plt.title("SCP download aws-london <- us-west-oregon") # Title of chart
	#plt.ylabel("MB/sec") # y-label 
	#ax1.axes.get_xaxis().set_visible(False)
	#ax2.axes.get_yaxis().set_visible(False)
	#autolabel(rec1, ax1)
	#autolabel(rec2, ax2)
	#autolabel(rec3, ax3)
	#autolabel(rec4, ax4)

	plt.plot(figsize=(50, 50), orientation=u'horizontal')
	plt.tight_layout()
	plt.show()
