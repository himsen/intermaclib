#!/usr/bin/python2.7

import os
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec

# Header size in a log file
HEADER_SIZE = 6

# Relative path to log directory
# 1kb, 8kb, 15kb, 50kb
LOG_DIR_CONSTANT = './libim_logs/log_constant_time'
LOG_DIR_NO_CONSTANT = './libim_logs/log_no_constant_time'

NUMBER_OF_FUNCTIONS = 1
functions = ['decrypt']
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
NUMBER_OF_MSG_SIZES = 1
msg_sizes = [
	8 * 1024, # 8kb
	]

# Data lists
list_dec_aes_gcm_constant = 'decrypt_aes128-gcm'
decrypt_aes128_gcm_constant = [0] * NUMBER_OF_CHUNK_LENGTHS
list_dec_chacha_poly_constant = 'decrypt_chacha-poly'
decrypt_chacha_poly_constant = [0] * NUMBER_OF_CHUNK_LENGTHS

list_dec_aes_gcm_no_constant = 'decrypt_aes128-gcm'
decrypt_aes128_gcm_no_constant = [0] * NUMBER_OF_CHUNK_LENGTHS
list_dec_chacha_poly_no_constant = 'decrypt_chacha-poly'
decrypt_chacha_poly_no_constant = [0] * NUMBER_OF_CHUNK_LENGTHS

def print_data_parsed(root_list, name):

	print 'Parsed data for: {}\n'.format(name)

	print 'List: {}\n'.format(cycles_per_byte(root_list, msg_sizes[0]))
		#

def cycles_per_byte(data, size):

	return [ ( x / size) for x in data ]

def map_list_constant(function, cipher):

	l = None
	string = '{}_{}'.format(function, cipher)

	if (list_dec_aes_gcm_constant == string):
		l = decrypt_aes128_gcm_constant
	elif (list_dec_chacha_poly_no_constant == string):
		l = decrypt_chacha_poly_constant

	return l

def map_list_no_constant(function, cipher):

	l = None
	string = '{}_{}'.format(function, cipher)

	if (list_dec_aes_gcm_no_constant == string):
		l = decrypt_aes128_gcm_no_constant
	elif (list_dec_chacha_poly_no_constant == string):
		l = decrypt_chacha_poly_no_constant

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
	for file in os.listdir(LOG_DIR_CONSTANT):
		# Grab log files
		if file.startswith('libim_bench_'):
			with open(os.path.join(LOG_DIR_CONSTANT, file), 'r') as fd:

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
				data = map_list_constant(function, cipher)

				# Only proceed if we could map the name to a list
				if (data != None):
					for j in range (0, NUMBER_OF_CHUNK_LENGTHS):
						data[j] = float(log[HEADER_SIZE + 1 + j*2 + 1])

				print_data_parsed(data, '{} with {}'.format(function, cipher))

	# Cycle through all files in directory
	for file in os.listdir(LOG_DIR_NO_CONSTANT):
		# Grab log files
		if file.startswith('libim_bench_'):
			with open(os.path.join(LOG_DIR_NO_CONSTANT, file), 'r') as fd:

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
				data = map_list_no_constant(function, cipher)

				# Only proceed if we could map the name to a list
				if (data != None):
					for j in range (0, NUMBER_OF_CHUNK_LENGTHS):
						data[j] = float(log[HEADER_SIZE + 1 + j*2 + 1])

				print_data_parsed(data, '{} with {}'.format(function, cipher))

def draw_graph_combined(ax, ylabels, data1, data2, msg_length, max_x_label):

	y = np.arange(len(ylabels))
	height = 0.35

	rec1 = ax.barh(y, data1, height, align='center', color='red')
	rec2 = ax.barh(y + height, data2, height, align='center', color='blue')

	ax.set_title('{}'.format(msg_length))

	ax.set_yticks(y + height / 2)
	ax.set_yticklabels(ylabels)
	ax.set_ylabel('chunk length')
	
	ax.set_xlabel('cycles / byte')
	ax.set_xlim(0, max_x_label)
	ax.set_ylim(-0.5,14)

	ax.legend((rec2[0], rec1[0]), ('chacha20-poly1305','aes128-gcm'), loc='center right', prop={'size': 8})
	
	ax.xaxis.grid(color='green', linestyle='-')

def draw_graph_split(ax, ylabels, data, msg_length, max_x_label, label_data):

	y = np.arange(len(ylabels))
	height = 0.35

	rec1 = ax.barh(y, data, height, align='center', color='red', label=label_data)

	ax.set_title('{}'.format(msg_length))

	ax.set_yticks(y)
	ax.set_yticklabels(ylabels)
	ax.set_ylabel('chunk length')
	
	ax.set_xlabel('cycles / byte')
	ax.set_xlim(0, max_x_label)
	ax.set_ylim(-0.5,14-0.5)

	ax.legend(loc='center right', prop={'size': 8})
	
	ax.xaxis.grid(color='green', linestyle='-')

def do_graphs_grid_combined(str_select):

	data1 = None
	data2 = None

	eightkb = msg_sizes[0]

	max_x_label_eightkb = 95

	fig = plt.figure(figsize=(9,4.5))

	fig.suptitle('{}()'.format(str_select), fontsize=22)

	gs = gridspec.GridSpec(1, 2, width_ratios=[1, 1])
	ax1 = plt.subplot(gs[0])
	ax2 = plt.subplot(gs[1])
	
	draw_graph_combined(
		ax1,
		chunk_lengths,
		cycles_per_byte(decrypt_aes128_gcm_constant, eightkb),
		cycles_per_byte(decrypt_chacha_poly_constant, eightkb),
		'Constant Time',
		max_x_label_eightkb)
	draw_graph_combined(
		ax2,
		chunk_lengths,
		cycles_per_byte(decrypt_aes128_gcm_no_constant, eightkb),
		cycles_per_byte(decrypt_chacha_poly_no_constant, eightkb),
		'Non-Constant Time',
		max_x_label_eightkb)

	plt.tight_layout(pad=1, w_pad=1, h_pad=1, rect=[0, 0, 1, 0.97])
	plt.show()

def do_graphs_grid_split(str_select):

	data1 = None
	data2 = None

	eightkb = msg_sizes[0]

	max_x_label_eightkb_aes_gcm = 30
	max_x_label_eightkb_chacha_poly = 100


	fig = plt.figure(figsize=(9,9))

	fig.suptitle('{}()'.format(str_select), fontsize=22)

	gs = gridspec.GridSpec(2, 2, width_ratios=[1, 1])
	ax1 = plt.subplot(gs[0])
	ax2 = plt.subplot(gs[1])
	ax3 = plt.subplot(gs[2])
	ax4 = plt.subplot(gs[3])
	
	draw_graph_split(
		ax1,
		chunk_lengths,
		cycles_per_byte(decrypt_aes128_gcm_constant, eightkb),
		'Constant Time',
		max_x_label_eightkb_aes_gcm,
		'aes128-gcm')
	draw_graph_split(
		ax2,
		chunk_lengths,
		cycles_per_byte(decrypt_aes128_gcm_no_constant, eightkb),
		'Non-Constant Time',
		max_x_label_eightkb_aes_gcm,
		'aes128-gcm')
	draw_graph_split(
		ax3,
		chunk_lengths,
		cycles_per_byte(decrypt_chacha_poly_constant, eightkb),
		'Constant Time',
		max_x_label_eightkb_chacha_poly,
		'chacha20-poly1305')
	draw_graph_split(
		ax4,
		chunk_lengths,
		cycles_per_byte(decrypt_chacha_poly_no_constant, eightkb),
		'Non-Constant Time',
		max_x_label_eightkb_chacha_poly,
		'chacha20-poly1305')

	plt.tight_layout(pad=1, w_pad=1, h_pad=1, rect=[0, 0, 1, 0.97])
	plt.show()

if __name__ == '__main__':

	parse_logs()

	#do_graphs_grid_combined('decrypt')
	do_graphs_grid_split('decrypt')
