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

	if (list_enc_aes_gcm == string):
		l = encrypt_aes128_gcm
	elif (list_dec_aes_gcm == string):
		l = decrypt_aes128_gcm
	elif (list_enc_chacha_poly == string):
		l = encrypt_chacha_poly
	elif (list_dec_chacha_poly == string):
		l = decrypt_chacha_poly

	return l

def parse_logs():

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

				# Only proceed if we could map the name to a list
				if (data != None):
					# For each msg size, and for each chunk length,
					# retrieve the measured clock cycles
					for i in range(0, NUMBER_OF_MSG_SIZES):
						sub_data = data[i]
						for j in range (0, NUMBER_OF_CHUNK_LENGTHS):
							sub_data[j] = float(log[HEADER_SIZE + (i + 1) + ((NUMBER_OF_CHUNK_LENGTHS * 2) * i) + j*2 + 1])

					print_data_parsed(data, '{} with {}'.format(function, cipher))

def draw_graph(ax, ylabels, data1, data2, msg_length, max_x_label):

	y = np.arange(len(ylabels))
	height = 0.35

	rec1 = ax.barh(y, data1, height, align='center', color='red')
	rec2 = ax.barh(y + height, data2, height, align='center', color='blue')

	ax.set_title('{}'.format(msg_length))

	ax.set_yticks(y + height / 3)
	ax.set_yticklabels(ylabels)
	ax.set_ylabel('chunk length')
	
	ax.set_xlabel('cycles / byte')
	ax.set_xlim(0, max_x_label)
	ax.set_ylim(-0.5,14)

	ax.legend((rec2[0], rec1[0]), ('chaCha20-poly1305','aes128-gcm'), loc='center right', prop={'size': 10})
	
	ax.xaxis.grid(color='green', linestyle='-')


	#for r in rec:
	#	w = r.get_width()
	#	if not w == 0:	
	#		ax.text(10, r.get_y() + 0.5, '{}'.format(w), color='blue', fontweight='bold')

def cycles_per_byte(data, size):

	return [ ( x / size) for x in data ]

def do_graphs_grid(str_select):

	data1 = None
	data2 = None

	onekb = 1024
	eightkb = 8 * 1024
	fifteenkb = 15 * 1024
	fiftykb = 50 * 1024

	if (str_select == 'encrypt'):
		data1 = encrypt_aes128_gcm
		data2 = encrypt_chacha_poly
		max_x_label_onekb = 70
		max_x_label_eightkb = 70
		max_x_label_fifteenkb = 70
		max_x_label_fiftykb = 70
	elif (str_select == 'decrypt'):
		data1 = decrypt_aes128_gcm
		data2 = decrypt_chacha_poly
		max_x_label_onekb = 70
		max_x_label_eightkb = 70
		max_x_label_fifteenkb = 70
		max_x_label_fiftykb = 70

	fig = plt.figure(figsize=(10,10))

	fig.suptitle('{}()'.format(str_select), fontsize=22)

	gs = gridspec.GridSpec(2, 2, width_ratios=[1, 1], height_ratios=[1,1])
	ax1 = plt.subplot(gs[0])
	ax2 = plt.subplot(gs[1])
	ax3 = plt.subplot(gs[2])
	ax4 = plt.subplot(gs[3])
	
	draw_graph(
		ax1,
		chunk_lengths,
		cycles_per_byte(data1[0], onekb),
		cycles_per_byte(data2[0], onekb),
		'1kb',
		max_x_label_onekb)
	draw_graph(
		ax2,
		chunk_lengths,
		cycles_per_byte(data1[1], eightkb),
		cycles_per_byte(data2[1], eightkb),
		'8kb',
		max_x_label_eightkb)
	draw_graph(
		ax3,
		chunk_lengths,
		cycles_per_byte(data1[2], fifteenkb),
		cycles_per_byte(data2[2], fifteenkb),
		'15kb',
		max_x_label_fifteenkb)
	draw_graph(
		ax4,
		chunk_lengths,
		cycles_per_byte(data1[3], fiftykb),
		cycles_per_byte(data2[3], fiftykb),
		'50kb',
		max_x_label_fiftykb)

	plt.tight_layout(pad=1, w_pad=1, h_pad=1, rect=[0, 0, 1, 0.97])
	plt.show()

if __name__ == '__main__':

	parse_logs()

	do_graphs_grid('decrypt')
