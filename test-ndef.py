#!/usr/bin/python
#
# test-ndef.py -- load an NDEF object from a binary file and print it
#
# This script adds support for the kerberos-specific types for NDEF.
#
# From: Rick van Rein <rick@openfortress.nl>


import sys
import ndef


class KerberosTicket (ndef.Record):

	"""This class handles NDEF records holding Kerberos tickets.
	"""

	_type = 'urn:nfc:ext:arpa2.org:krb5:ticket'

	def __init__ (self, tkt):
		self.ticket = tkt

	def _encode_payload (self):
		return self.ticket

	def __len__ (self):
		return len (self.ticket)

	@classmethod
	def _decode_payload (cls, octets, errors):
		return cls (octets)


class KerberosEncTicketPartKeytab (ndef.Record):

	"""This class handles NDEF records holding Kerberos' EncTicketPart
	   structures, encrypted with a key found in a keytab.
	"""

	_type = 'urn:nfc:ext:arpa2.org:krb5:encticketpart:keytab'

	def __init__ (self, etp):
		self.encticketpart = etp

	def _encode_payload (self):
		return self.encticketpart

	def __len__ (self):
		return len (self.encticketpart)

	@classmethod
	def _decode_payload (cls, octets, errors):
		return cls (octets)

ndef.Record.register_type (KerberosTicket)
ndef.Record.register_type (KerberosEncTicketPartKeytab)


if len (sys.argv) != 2:
	sys.stderr.write ('Usage: ' + sys.argv [0] + ' object.ndef\n')
	sys.exit (1)

obj = open (sys.argv [1]).read (99999999)

for rec in ndef.message_decoder (obj):
	print 'Record length', len (rec), 'and type', type (rec)

