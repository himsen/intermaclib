#!/usr/bin/python2.7

import os
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec

# Header size in a log file
HEADER_SIZE = 6

# Relative path to log directory
# 1kb, 8kb, 15kb, 50kb
LOG_DIR = './libim_logs/log_new'

NUMBER_OF_FUNCTIONS = 2
functions = ['encrypt', 'decrypt']
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
NUMBER_OF_MSG_SIZES = 4

# Data lists
list_enc_aes_gcm = 'encrypt_aes128-gcm'
encrypt_aes128_gcm = [[0] * NUMBER_OF_CHUNK_LENGTHS for i in range(NUMBER_OF_MSG_SIZES)]
list_dec_aes_gcm = 'decrypt_aes128-gcm'
decrypt_aes128_gcm = [[0] * NUMBER_OF_CHUNK_LENGTHS for i in range(NUMBER_OF_MSG_SIZES)]
list_enc_chacha_poly = 'encrypt_chacha-poly'
encrypt_chacha_poly = [[0] * NUMBER_OF_CHUNK_LENGTHS for i in range(NUMBER_OF_MSG_SIZES)]
list_dec_chacha_poly = 'decrypt_chacha-poly'
decrypt_chacha_poly = [[0] * NUMBER_OF_CHUNK_LENGTHS for i in range(NUMBER_OF_MSG_SIZES)]

def print_data_parsed(root_list, name):

	print 'Parsed data for: {}\n'.format(name)

	for i in range(NUMBER_OF_MSG_SIZES):
		print 'List {}: {}\n'.format(i, root_list[i])

def map_list(function, cipher):

	l = None
	string = '{}_{}'.format(function, cipher)

	if list_enc_aes_gcm == string:
		l = encrypt_aes128_gcm
	elif list_dec_aes_gcm == string:
		l = decrypt_aes128_gcm
	elif list_enc_chacha_poly == string:
		l = encrypt_chacha_poly
	elif list_dec_chacha_poly == string:
		l = decrypt_chacha_poly

	return l

def parse_logs():

	res = 0
	data = None
	sub_data = None
	date = None
	function = None
	cipher = None
	warmup_size = 0
	complexity_size = 0
	stat_size = 0
	chunk_length = 0
	msg_size = 0

	#print os.listdir(LOG_DIR)

	# Cycle through all files in directory
	for file in os.listdir(LOG_DIR):
		# Grab log files
		if file.startswith('libim_bench_'):
			with open(os.path.join(LOG_DIR, file), 'r') as fd:

				# Split by newline
				log = fd.read().split('\n')

				# Get header info
				# (data, function, cipher, warmup, complexity, stat)
				date = log[0]
				function = log[1]
				cipher = log[2]
				warmup_size = int(log[3])
				complexity_size = int(log[4])
				stat_size = int(log[5])

				# Switch median list
				data = map_list(function, cipher)

				# For each msg size, and for each chunk length,
				# retrieve the measured clock cycles
				for i in range(0, NUMBER_OF_MSG_SIZES):
					sub_data = data[i]
					for j in range (0, NUMBER_OF_CHUNK_LENGTHS):
						sub_data[j] = float(log[HEADER_SIZE + (i + 1) + ((NUMBER_OF_CHUNK_LENGTHS * 2) * i) + j*2 + 1])

				print_data_parsed(decrypt_aes128_gcm, 'DECRYPT with aes128-gcm')

def draw_graph(ax, ylabels, data_medians, function, x_label_if):

	# Max x-label 1kb
	#max_x_label = 300000
	# Max x-label 10kb
	#max_x_label = 680000
	# Max x-label 100kb
	#max_x_label = 6500000
	# Max x-label 1mb
	#if (x_label_if == 1):
	#	max_x_label = 68000000
	#elif (x_label_if == 2):
	#	max_x_label = 15000000

	if (x_label_if == 1):
		max_x_label = 68
	elif (x_label_if == 2):
		max_x_label = 15

	y = np.arange(len(ylabels) * 2, step=2)
	height = 1.2

	rec = ax.barh(y, data_medians, height, align='center', color='red')
	ax.set_title('{}'.format(function))
	ax.set_yticks(y)
	ax.set_yticklabels(ylabels)
	ax.set_ylabel('chunk length')
	#ax.invert_yaxis()
	ax.set_xlabel('clock cycles / byte')
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
	draw_graph(ax3, chunk_lengths, [ (x / SIZE) for x in medians_encrypt_aes128_gcm], 'encrypt() - aes128-gcm', 2)
	draw_graph(ax4, chunk_lengths, [ (x / SIZE) for x in medians_encrypt_chacha_poly], 'encrypt() - chacha20-poly1305', 1)
	draw_graph(ax5, chunk_lengths, [ (x / SIZE) for x in medians_decrypt_aes128_gcm], 'decrypt() - aes128-gcm', 2)
	draw_graph(ax6, chunk_lengths, [ (x / SIZE) for x in medians_decrypt_chacha_poly], 'decrypt() - chacha20-poly1305', 1)

	#fig.suptitle('Median time for functions initialise(), encrypt() and decrypt() in libInterMAC for different chunk lenths', fontsize=18)
	#plt.tight_layout(pad=4, w_pad=-8, h_pad=1)
	plt.show()

def do_graphs_grid():

	fig = plt.figure(figsize=(9,9))

	gs = gridspec.GridSpec(2, 2, width_ratios=[1, 2], height_ratios=[1,1])
	ax1 = plt.subplot(gs[0])
	ax2 = plt.subplot(gs[1])
	ax3 = plt.subplot(gs[2])
	ax4 = plt.subplot(gs[3])

	draw_graph(ax1, chunk_lengths, [ (x / SIZE) for x in medians_encrypt_aes128_gcm], 'encrypt() - aes128-gcm', 2)
	draw_graph(ax2, chunk_lengths, [ (x / SIZE) for x in medians_encrypt_chacha_poly], 'encrypt() - chacha20-poly1305', 1)
	draw_graph(ax3, chunk_lengths, [ (x / SIZE) for x in medians_decrypt_aes128_gcm], 'decrypt() - aes128-gcm', 2)
	draw_graph(ax4, chunk_lengths, [ (x / SIZE) for x in medians_decrypt_chacha_poly], 'decrypt() - chacha20-poly1305', 1)

	plt.tight_layout(pad=1, w_pad=1, h_pad=1)
	plt.show()

if __name__ == '__main__':

	parse_logs()

	#do_graphs_grid()
