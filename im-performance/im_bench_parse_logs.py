#!/usr/bin/python2

import os
import numpy as np
import matplotlib.pyplot as plt
import statistics

# Header size in a log file
HEADER_SIZE = 5

# Relative path to log directory
# 1kb
#LOG_DIR = './libim_logs/log_1024'
# 10kb
#LOG_DIR = './libim_logs/log_10_1024'
# 100kb
#LOG_DIR = './libim_logs/log_100_1024'
# 1mb
LOG_DIR = './libim_logs/log_1024_1024'

NUMBER_OF_FUNCTIONS = 3
functions = ['initialise', 'encrypt', 'decrypt']
NUMBER_OF_CIPHERS = 2
ciphers = ['aes128-gcm', 'chacha-poly']
NUMBER_OF_CHUNK_LENGTHS = 14
chunk_lengths = [
	127,
	128,
	255,
	256,
	511,
	512,
	1023,
	1024,
	2047,
	2048,
	4095,
	4096,
	8191,
	8192]

# Ugly...
list_ini_aes_gcm = 'initialise_aes128-gcm'
medians_initialise_aes128_gcm = []
list_ini_chacha_poly = 'initialise_chacha-poly'
medians_initialise_chacha_poly = []
list_enc_aes_gcm = 'encrypt_aes128-gcm'
medians_encrypt_aes128_gcm = []
list_enc_chacha_poly = 'encrypt_chacha-poly'
medians_encrypt_chacha_poly = []
list_dec_aes_gcm = 'decrypt_aes128-gcm'
medians_decrypt_aes128_gcm = []
list_dec_chacha_poly = 'decrypt_chacha-poly'
medians_decrypt_chacha_poly = []

def choose_median_list(function, cipher):

	medians = None
	string = '{}_{}'.format(function, cipher)

	if list_ini_aes_gcm == string:
		medians = medians_initialise_aes128_gcm
	elif list_ini_chacha_poly == string:
		medians = medians_initialise_chacha_poly
	elif list_enc_aes_gcm == string:
		medians = medians_encrypt_aes128_gcm
	elif list_enc_chacha_poly == string:
		medians = medians_encrypt_chacha_poly
	elif list_dec_aes_gcm == string:
		medians = medians_decrypt_aes128_gcm
	elif list_dec_chacha_poly == string:
		medians = medians_decrypt_chacha_poly

	return medians

def parse_logs():

	data = None
	medians = None
	function = None
	cipher = None
	warmup_size = 0
	stat_size = 0
	chunk_length = 0
	msg_size = 0

	print os.listdir(LOG_DIR)
	# Cycle through all files in directory
	for file in os.listdir(LOG_DIR):
		# Grab log files
		if file.startswith('libim_bench_'):
			with open(os.path.join(LOG_DIR, file), 'r') as fd:

				# Split by newline
				log = fd.read().split('\n')

				# Get header info
				# (function, cipher, message size, warmup size, stat size)
				function = log[0]
				cipher = log[1]
				msg_size = int(log[2])
				warmup_size = int(log[3])
				stat_size = int(log[4])

				# Switch median list
				medians = choose_median_list(function, cipher)

				# For each chunk length, retrieve the data and
				# compute median and append to list
				# Remember to jump the chunk length
				for i in range(0, NUMBER_OF_CHUNK_LENGTHS):

					data = log[HEADER_SIZE + (i * (stat_size + 1)):
						HEADER_SIZE + (i * (stat_size + 1)) + stat_size]

					# Compute and append median
					medians.append(np.median(map(float,data)))

def draw_graph(ax, ylabels, data_medians, function):

	# Max x-label 1kb
	#max_x_label = 300000
	# Max x-label 10kb
	#max_x_label = 680000
	# Max x-label 100kb
	#max_x_label = 6500000
	# Max x-label 1mb
	max_x_label = 68000000

	y = np.arange(len(ylabels) * 2, step=2)
	height = 1.2

	rec = ax.barh(y, data_medians, height, align='center', color='red')
	ax.set_title('function: {}'.format(function))
	ax.set_yticks(y)
	ax.set_yticklabels(ylabels)
	#ax.invert_yaxis()
	ax.set_xlabel('clock cycles')
	ax.set_xlim(0, max_x_label)
	ax.set_ylim(-1.5,28-0.5)
	
	ax.grid(color='green', linestyle='-')

	#for r in rec:
	#	w = r.get_width()
	#	if not w == 0:	
	#		ax.text(10, r.get_y() + 0.5, '{}'.format(w), color='blue', fontweight='bold')

def do_graphs():

	#fig, axes = plt.subplots(nrows=3, ncols=2, figsize=(10,10))
	fig, axes = plt.subplots(nrows=2, ncols=2, figsize=(10,10))

	#ax1, ax2, ax3, ax4, ax5, ax6 = axes.flatten()
	ax3, ax4, ax5, ax6 = axes.flatten()

	#draw_graph(ax1, chunk_lengths, medians_initialise_aes128_gcm, 'initialise() - aes128-gcm')
	#draw_graph(ax2, chunk_lengths, medians_initialise_chacha_poly, 'initialise() - chacha20-poly1305')
	draw_graph(ax3, chunk_lengths, medians_encrypt_aes128_gcm, 'encrypt() - aes128-gcm')
	draw_graph(ax4, chunk_lengths, medians_encrypt_chacha_poly, 'encrypt() - chacha20-poly1305')
	draw_graph(ax5, chunk_lengths, medians_decrypt_aes128_gcm, 'decrypt() - aes128-gcm')
	draw_graph(ax6, chunk_lengths, medians_decrypt_chacha_poly, 'decrypt() - chacha20-poly1305')

	#fig.suptitle('Median time for functions initialise(), encrypt() and decrypt() in libInterMAC for different chunk lenths', fontsize=18)
	#plt.tight_layout(pad=4, w_pad=-8, h_pad=1)
	plt.show()


if __name__ == '__main__':

	parse_logs()

	print 'Medians {}:\n{}'.format(list_ini_aes_gcm, medians_initialise_aes128_gcm)
	print 'Medians {}:\n{}'.format(list_ini_chacha_poly, medians_initialise_chacha_poly)
	print 'Medians {}:\n{}'.format(list_enc_aes_gcm, medians_encrypt_aes128_gcm)
	print 'Medians {}:\n{}'.format(list_enc_chacha_poly, medians_encrypt_chacha_poly)
	print 'Medians {}:\n{}'.format(list_dec_aes_gcm, medians_decrypt_aes128_gcm)
	print 'Medians {}:\n{}'.format(list_dec_chacha_poly, medians_decrypt_chacha_poly)

	do_graphs()
