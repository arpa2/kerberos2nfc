#!/usr/bin/env python
#
# ndef2mfd.py -- Place an NDEF file in a Mifare card
#
# For now, we're only supporting Mifare Classic 1k or S50 cards.  Their binary
# content is read and written by libnfc utility nfc-mfclassic using a dump
# format known as MFD.
#
# This program reads an MFD file, modifies its data to setup a MAD and the
# proper access rights for the card, and then writes out a new MFD file.
#
# THIS IS JUST FOR FUN.  You should not rely on the security of S50 cards,
# they have been shown to be totally insecure.  Use them as a data carrier
# for your business card, but then be prepared to see the data change while
# you present it to others.  DO NOT RELY ON S50 SECURITY but, by all means,
# have some fun with this if you happen to have the cards wasting away.
# Repossess your Dutch OV-kaart, for example.
#
# From: Rick van Rein <rick@openfortress.nl>


import sys
import struct


#
# The write key, for now left to the default value
#
keyB = [ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff ]


if len (sys.argv) != 4:
	sys.stderr.write ('Usage: ' + sys.argv [0] + ' in.mfd tag.ndef out.mfd\n')
	sys.exit (1)

if sys.argv [1] == sys.argv [2]:
	sys.stderr.write ('You must supply different file names for input and output\n')
	sys.exit (1)

in_mfd = sys.argv [1]
tag_ndef = sys.argv [2]
out_mfd = sys.argv [3]

miffy = open (in_mfd, 'r').read (1025)
if len (miffy) != 1024:
	sys.stderr.write ('Your input file should have an exact length of 1024 bytes\n')
	sys.exit (1)
miffy = [ ord(c) for c in miffy ]

#
# Collect the payload blocks
#
ndef = open (tag_ndef, 'r').read (1025)
if len (ndef) <= 0xfe:
	head = struct.pack ('BB',
			0x03,				# NDEF message TLV.tag
			len (ndef))			# short-form length
elif len (ndef) <= 0xfffe:
	head = struct.pack ('BBBB',
			0x03,				# NDEF message TLV.tag
			0xff,				# long-form length
			len (ndef) >> 8, len (ndef) & 0xff)
tail = struct.pack ('B', 0xfe)				# Terminator TLV.tag
payload = [ ord(c) for c in head + ndef + tail ]
space_1k = 16 * 3 * 15
print 'NDEF with TLV head & tail:', len (payload)
if len (payload) > space_1k:
	sys.stderr.write ('Your NDEF data is too long to fit on a Mifare Classic 1k, sorry\n')
	sys.exit (1)


#
# Write the MAD into sector 0, as follows:
#  - block0: copy UID / manufacturer codes (16 bytes)
#  - block1, first 2 bytes: fill with CRC, info
#     - info (as MAD1)
#     - CRC-8, preset 0xe3, x8+x4+3+x2+1 over block1 [1..15] en block2 [0..15]
#     - info and CRC-8 are app-fixed :) so set to 0x14,0x01
#  - block1 rest, block2: fill with AID 0x03,0xe1
#  - block3, keyA: 0xa0,0xa1,0xa2,0xa3,0xa4,0xa5 (MAD access key)
#  - block3, access: 0x78,0x77,0x88
#  - block3, gpb: 0xc1
#  - block3, keyB: 0xff,0xff,0xff,0xff,0xff,0xff (to be writing secret)
#
miffy [0x10] = 0x14					# Fixed CRC
miffy [0x11] = 0x01					# Info byte
for i in range (0x12,0x30,2):
	miffy [i+0] = 0x03				# AID.0
	miffy [i+1] = 0xe1				# AID.1
for i in range (6):
	miffy [0x30+i] = 0xa0 + i			# MAD access key --> keyA
	miffy [0x3a+i] = keyB [i]			# Write key      --> keyB
miffy [0x36] = 0x78					# access.0
miffy [0x37] = 0x77					# access.1
miffy [0x38] = 0x88					# access.2
miffy [0x39] = 0xc1					# GPB

#
# Write application data to sectors 1..15, as follows:
#  - block 0, block1, block2: application data: TLV, NDEF, emptyTLV
#  - block 3, key A: 0xd3,0xf7,0xd3,0xf7,0xd3,0xf7 (Public NDEF key)
#  - block 3, access: 0x7f,0x07,0x88
#  - block 3, gpb: 0x40
#  - block 3, keyB: 0xff,0xff,0xff,0xff,0xff,0xff (to be writing secret)
#
sector = 0x40
payrest = payload
while len (payrest) > 0:
	payhere = payrest [:0x30]
	payrest = payrest [0x30:]
	for i in range (len (payhere)):
		miffy [sector + i] = payhere [i]
	for i in [0x30,0x32,0x34]:
		miffy [sector+i+0] = 0xd3		# NFC public key --> keyA
		miffy [sector+i+1] = 0xf7		# NFC public key --> keyA
	miffy [sector+0x36] = 0x7f			# access.0
	miffy [sector+0x37] = 0x07			# access.1
	miffy [sector+0x38] = 0x88			# access.2
	miffy [sector+0x39] = 0x40			# GPB
	for i in range (6):
		miffy [sector+0x3a+i] = keyB [i]	# Write key      --> keyB
	sector = sector + 0x40


#
# Write out the new MFD file
#
outb = ''.join ([chr (c) for c in miffy])
outf = open (out_mfd, 'w')
outf.write (outb)
outf.close ()
print 'Wrote', len (outb), 'bytes to', out_mfd


