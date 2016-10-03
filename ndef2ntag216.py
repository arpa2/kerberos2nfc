#!/usr/bin/env python
#
# ndef2ntag216.py -- Place an NDEF file in a Mifare NTAG216 card
#
# For now, we're only supporting Mifare NTAG 216 cards.  Their binary
# content is read and written by libnfc utility nfc-mfclassic using a dump
# format known as MFD.
#
# This program reads an MFD file, modifies its data to hold the NDEF values
# for the card, and then writes out a new MFD file.
#
# THIS IS JUST FOR FUN.  The security status of NTAG 216 has not been
# established by us, but the reputation of Mifare Classic 1k is widely
# known to be highly unreliable.  Do your homework or be at risk.
#
# From: Rick van Rein <rick@openfortress.nl>


import sys
import struct


if len (sys.argv) != 4:
	sys.stderr.write ('Usage: ' + sys.argv [0] + ' in.mfd tag.ndef out.mfd\n')
	sys.exit (1)

if sys.argv [1] == sys.argv [2]:
	sys.stderr.write ('You must supply different file names for input and output\n')
	sys.exit (1)

in_mfd = sys.argv [1]
tag_ndef = sys.argv [2]
out_mfd = sys.argv [3]

miffy = open (in_mfd, 'r').read (917)
if len (miffy) != 916:
	sys.stderr.write ('Your input file should have an exact length of 916 bytes\n')
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
space_216 = 888
print 'NDEF with TLV head & tail:', len (payload)
if len (payload) > space_216:
	sys.stderr.write ('Your NDEF data is too long to fit on an NTAG216, sorry\n')
	sys.exit (1)


#
# Write application data to 4-byte blocks at 0x10 .. 0x387 (inclusive)
#  - application data: TLV, NDEF, emptyTLV
#
for pos in range (len (payload)):
	miffy [0x010 + pos] = payload [pos]


#
# Write out the new MFD file
#
outb = ''.join ([chr (c) for c in miffy])
outf = open (out_mfd, 'w')
outf.write (outb)
outf.close ()
print 'Wrote', len (outb), 'bytes to', out_mfd


