#!/usr/bin/python2.7

import os
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec

# Header size in a log file
HEADER_SIZE = 6

# Relative path to log directory
# 1kb, 8kb, 15kb, 50kb
LOG_DIR = './libim_logs/log_ct'

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
msg_sizes = [
	1024, # 1kb
	8 * 1024, # 8kb
	15 * 1024, # 15kb
	50 * 1024 # 50kb
	]

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
		print 'List {}: {}\n'.format(i, cycles_per_byte(root_list[i], msg_sizes[i]))

def cycles_per_byte(data, size):

	return [ ( x / size) for x in data ]

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

def draw_graph(ax, ylabels, data1, data2, data3, data4, msg_length, max_x_label):

	height = 20
	distance = 10
	block = height * 4 + distance
	y1 = [block * i for i in range(14)]
	y2 = [block * i + height for i in range(14)]
	y3 = [block * i + height * 2 for i in range(14)]
	y4 = [block * i + height * 3 for i in range(14)]

	rec1 = ax.barh(y1, data1, height, align='center', color='#DA2256')
	rec2 = ax.barh(y2, data2, height, align='center', color='#FEBC38')
	rec3 = ax.barh(y3, data3, height, align='center', color='#D8C684')
	rec4 = ax.barh(y4, data4, height, align='center', color='#697F98')

	for bar in rec1:
		bar.set_hatch('/')
	for bar in rec2:
		bar.set_hatch('*')
	for bar in rec3:
		bar.set_hatch('x')
	for bar in rec4:
		bar.set_hatch('O')

	ax.set_title('{}'.format(msg_length), fontsize=40)

	ax.set_yticks([i - float(height / 2) for i in y3])
	ax.set_yticklabels(ylabels)
	ax.set_ylabel('chunk length', fontsize=40)
	
	ax.set_xlabel('cycles / byte', fontsize=40)
	ax.set_xlim(0, max_x_label)
	ax.set_ylim(- float(height / 2) - distance, block * 14 - distance - float(height / 2) + distance)

	ax.legend((rec4[0], rec3[0], rec2[0], rec1[0]), ('50KB', '15KB', '8KB','1KB'), loc='center right', prop={'size': 40})
	
	plt.setp(ax.get_xticklabels(), fontsize=35)
	plt.setp(ax.get_yticklabels(), fontsize=35)

	ax.xaxis.grid(color='black', linestyle='-')

def draw_graph_only_aes(ax, ylabels, data, msg_length, max_x_label):

	y = np.arange(len(ylabels))
	height = 0.35

	rec1 = ax.barh(y, data, height, align='center', color='red', label='aes128-gcm')

	ax.set_title('{}'.format(msg_length))

	ax.set_yticks(y)
	ax.set_yticklabels(ylabels)
	ax.set_ylabel('chunk length')
	
	ax.set_xlabel('cycles / byte')
	ax.set_xlim(0, max_x_label)
	ax.set_ylim(-0.5,14-0.5)

	ax.legend(loc='center right', prop={'size': 8})
	
	ax.xaxis.grid(color='black', linestyle='-')

def do_graphs_grid(str_select):

	data1 = None
	data2 = None

	onekb = msg_sizes[0]
	eightkb = msg_sizes[1]
	fifteenkb = msg_sizes[2]
	fiftykb = msg_sizes[3]

	if (str_select == 'encrypt'):
		data1 = encrypt_aes128_gcm
		data2 = encrypt_chacha_poly
		max_x_label_aes_gcm = 6
		max_x_label_chacha_poly = 95
	elif (str_select == 'decrypt'):
		data1 = decrypt_aes128_gcm
		data2 = decrypt_chacha_poly
		max_x_label_aes_gcm = 37
		max_x_label_chacha_poly = 125

	fig = plt.figure(figsize=(40,30))

	fig.suptitle('im_{}()'.format(str_select), fontsize=64)

	gs = gridspec.GridSpec(1, 2, width_ratios=[1,1])
	ax1 = plt.subplot(gs[0])
	ax2 = plt.subplot(gs[1])

	draw_graph(
		ax1,
		chunk_lengths,
		cycles_per_byte(data1[0], onekb),
		cycles_per_byte(data1[1], eightkb),
		cycles_per_byte(data1[2], fifteenkb),
		cycles_per_byte(data1[3], fiftykb),
		'aes128-gcm',
		max_x_label_aes_gcm)
	draw_graph(
		ax2,
		chunk_lengths,
		cycles_per_byte(data2[0], onekb),
		cycles_per_byte(data2[1], eightkb),
		cycles_per_byte(data2[2], fifteenkb),
		cycles_per_byte(data2[3], fiftykb),
		'chacha20-poly1305',
		max_x_label_chacha_poly)


	plt.tight_layout(pad=1, w_pad=1, h_pad=1.5, rect=[0, 0, 1, 0.95])
	#plt.show()
	plt.savefig("grouped_msg.png")

def do_graphs_grid_only_aes(str_select):

	data1 = None
	data2 = None

	onekb = msg_sizes[0]
	eightkb = msg_sizes[1]
	fifteenkb = msg_sizes[2]
	fiftykb = msg_sizes[3]

	if (str_select == 'encrypt'):
		data = encrypt_aes128_gcm
		max_x_label_onekb = 13
		max_x_label_eightkb = 6
		max_x_label_fifteenkb = 6
		max_x_label_fiftykb = 6
	elif (str_select == 'decrypt'):
		data = decrypt_aes128_gcm
		max_x_label_onekb = 85
		max_x_label_eightkb = 20
		max_x_label_fifteenkb = 15
		max_x_label_fiftykb = 15

	fig = plt.figure(figsize=(9,9))

	fig.suptitle('{}()'.format(str_select), fontsize=36)

	gs = gridspec.GridSpec(2, 2, width_ratios=[1, 1], height_ratios=[1,1])
	ax1 = plt.subplot(gs[0])
	ax2 = plt.subplot(gs[1])
	ax3 = plt.subplot(gs[2])
	ax4 = plt.subplot(gs[3])
	
	draw_graph_only_aes(
		ax1,
		chunk_lengths,
		cycles_per_byte(data[0], onekb),
		'1kb',
		max_x_label_onekb)
	draw_graph_only_aes(
		ax2,
		chunk_lengths,
		cycles_per_byte(data[1], eightkb),
		'8kb',
		max_x_label_eightkb)
	draw_graph_only_aes(
		ax3,
		chunk_lengths,
		cycles_per_byte(data[2], fifteenkb),
		'15kb',
		max_x_label_fifteenkb)
	draw_graph_only_aes(
		ax4,
		chunk_lengths,
		cycles_per_byte(data[3], fiftykb),
		'50kb',
		max_x_label_fiftykb)

	plt.tight_layout(pad=1, w_pad=1, h_pad=1, rect=[0, 0, 1, 0.97])
	plt.show()

if __name__ == '__main__':

	parse_logs()

	do_graphs_grid('decrypt')
	#do_graphs_grid('encrypt')
	#do_graphs_grid_only_aes('decrypt')
	#do_graphs_grid_only_aes('encrypt')