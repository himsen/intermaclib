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

	for file in os.listdir(dname):
		if file.endswith(".log"):
			with open(os.path.join(dname, file), 'r') as f:
				log = f.read().split('\n')
				for i in range(OFFSET_HEADER, len(log)-1, 4):
					if not xlabels_set:
						xlabels.append(log[i])

					index = xlabels.index(log[i])
					raw[index].append(log[i+1].replace(' ', '').split(':')[1])
					encrypted[index].append(log[i+2].replace(' ', '').split(':')[1])
					speed[index].append(log[i+3].rstrip().replace(' ', '').split(':')[1])

				xlabels_set = True	

	return xlabels, raw, encrypted, speed

if __name__ == '__main__':
	
	#xlabels, raw, encrypted, speed = parse_logs("logs/laptop-rhul-to-aws-london")
	#xlabels, raw, encrypted, speed = parse_logs("logs/aws-london-to-aws-us-west-oregon")
	#xlabels, raw, encrypted, speed = parse_logs("logs/dl-aws-london-to-aws-us-west-oregon")
	xlabels, raw, encrypted, speed = parse_logs("logs/ul-aws-london-to-aws-us-west-oregon")	

	rawmedian = []
	for i, l in enumerate(raw):
		rawmedian.append(np.median(map(int,l)))

	encryptedmedian = []
	for i, l in enumerate(encrypted):
		encryptedmedian.append(np.median(map(int,l)))

	speedmedian = []
	for i, l in enumerate(speed):
		speedmedian.append(np.median(map(float,l)))

	MB = 0.000001
	rawmedian = [ x * MB for x in rawmedian]
	encryptedmedian = [ x * MB for x in encryptedmedian]
	speedmedian = [ x * MB for x in speedmedian]


	x = np.arange(NUMBER_OF_CIPHERS * 2, step=2)
	width = 1.2

	fig, (ax1, ax2, ax3) = plt.subplots(ncols=3)

	rec1 = ax1.bar(x + 1, rawmedian, width, color='r')
	ax1.set_title("Total raw bytes")
	ax1.set_ylabel("MB")

	rec2 = ax2.bar(x + 1, encryptedmedian, width, color='r')
	ax2.set_title("Total encrypted bytes")

	rec3 = ax3.bar(x + 1, speedmedian, width, color='r')
	ax3.set_title("Throughput (500mb file)")
	#plt.xticks(x + (width / 2), xlabels, rotation=90, fontsize=10) # (position of x-labels, x-labels)

	def autolabel(rects, ax):
	    # Get y-axis height to calculate label position from.
	    (y_bottom, y_top) = ax.get_ylim()
	    i = 0
	    for rect in rects:
	        label_position = y_bottom + 0.3
	        ax.text(rect.get_x() + rect.get_width()/2 + 0.1, label_position,
	                xlabels[i],
	                ha='center', va='bottom', rotation=90, fontsize=10)
	        i = i + 1

	#plt.title("SCP download aws-london <- us-west-oregon") # Title of chart
	#plt.ylabel("MB/sec") # y-label 

	autolabel(rec1, ax1)
	autolabel(rec2, ax2)
	autolabel(rec3, ax3)

	plt.plot(figsize=(50, 50))
	plt.tight_layout()
	plt.show()
