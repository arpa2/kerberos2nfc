#
# kerberos2nfc utilities: ticket2ndef
#
# From: Rick van Rein <rick@openfortress.nl>


all: ticket2ndef


ticket2ndef: ticket2ndef.c
	gcc -O0 -ggdb3 -o $@ $< -lquickder -lkrb5

