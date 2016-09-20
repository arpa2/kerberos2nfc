## EXAMPLE SHELL SESSION TO RETRIEVE A TICKET AND ENCTICKETPART

> *This is not a fullblown demonstration of kerberos2nfc yet; it does however
> show that the desired information can be extracted from Kerberos.  The
> necessary encryption has not been applied yet, nor the actual packaging
> in NDEF format; these are relatively simple actions.*

Note that the format of the generated information is nice, and as it ought
to be under RFC4120.  That's a big concern out of the way.  Indeed, fetching
a ticket to a service (or defaulting to the TGT) and producing its key
material is quite possible.

Don't think this is crackable though... by the time you read this, the
temporary session key shown in the plain has already evaporated.  This is
precisely the point of using Kerberos with NFC Tags, that it does not
need the same level of scrutiny as a credential with an infinite life;
the fixed nature of NFC Tags suddenly becomes endurable.  Of course we
will in the end add encryption as well, because radio beacons should
not be beaconing out unprotected secrets to anyone.

    shell$ cat /dev/urandom | hexdump | head | sha256sum | cut -c 1-64
    
    7c5ad561cd4de6b14ba48d547d5c85a49eded66e4d840806f306970ef7a8c9ee

Let this be your key.  Now setup a keytab holding it:

    shell$ rm -f test.keytab
    
    shell$ ktutil
    
    ktutil: clear
    
    ktutil: addent -key -p 3123456789@TEL -k 1 -e aes256-cts-hmac-sha1-96
    
    Key for 3123456789@TEL (hex):
    
    ktutil: list
    
    slot KVNO Principal
    ---- ---- ---------------------------------------------------------------------
       1    1                           3123456789@TEL
    
    ktutil: wkt test.keytab
    
    ktutil: quit

Proceed to login to Kerberos,

    shell$ kinit -l 15m rick@ARPA2.NET
    
    Password for rick@ARPA2.NET: 
    
    shell$ klist 
    Ticket cache: FILE:/tmp/krb5cc_0
    Default principal: rick@ARPA2.NET
    
    Valid starting     Expires            Service principal
    20/09/16 18:12:22  20/09/16 18:27:20  krbtgt/ARPA2.NET@ARPA2.NET

Then it is time to export some ticket data:

    shell$ export KRB5_KTNAME=test.keytab

    shell$ ./ticket2ndef xmpp/xmpp.arpa2.net@ARPA2.NET 3123456789@TEL

    -----BEGIN CLIENT PRINCIPAL-----
    NameType: 1
    Name_0: rick
    Realm: ARPA2.NET
    -----END CLIENT PRINCIPAL-----
    
    -----BEGIN SERVICE PRINCIPAL-----
    NameType: 1
    Name_0: xmpp
    Name_1: xmpp.arpa2.net
    Realm: ARPA2.NET
    -----END SERVICE PRINCIPAL-----
    
    -----BEGIN TICKET HEXDUMP-----
    61 82 01 4c 30 82 01 48 a0 03 02 01 05 a1 0b 1b
    09 41 52 50 41 32 2e 4e 45 54 a2 21 30 1f a0 03
    02 01 01 a1 18 30 16 1b 04 78 6d 70 70 1b 0e 78
    6d 70 70 2e 61 72 70 61 32 2e 6e 65 74 a3 82 01
    0f 30 82 01 0b a0 03 02 01 12 a1 03 02 01 03 a2
    81 fe 04 81 fb 54 18 21 4d 18 f2 cf 8b 4c b7 7e
    fe 75 a3 98 c2 2c 36 9c d3 8a d9 e2 6a f6 43 0c
    09 43 2c 06 86 c7 bf 47 68 24 50 d0 66 5b 4e bd
    01 2f b2 0c f7 67 7a 3e 9a 95 0f ef d6 37 61 20
    aa a0 1b 36 6c a0 68 75 9e 4e b5 00 68 37 ed 98
    d5 f7 9a 38 84 23 71 85 52 42 c5 11 c0 52 b2 9a
    94 4b 77 31 fa 9e 03 bd 78 53 01 a4 9f 81 d4 35
    00 06 88 6b 1b 92 3c 56 ef 15 45 6a 2f 51 f8 79
    07 d9 bc 6e 50 4e 82 17 39 fe 20 d7 93 52 78 c5
    3f b8 b3 6e 17 63 d4 b2 00 cc 21 bf 8e 19 ed 1e
    0c 97 26 a5 6b e9 53 13 db 07 54 d0 1e bd d3 b4
    86 f9 24 22 9f ca 22 3e 4c 8d ee e0 dc d6 f1 9b
    11 c5 8d 16 ae ab ab b2 b8 0b 4d a2 b9 95 98 c4
    9c 60 e3 de f7 4e fb 53 62 16 2b 6a 05 65 85 65
    07 bd 91 c8 47 63 1e 9e 7f 3c cc ed f7 fb 7e cb
    d3 4a 2f 68 10 c0 7d 5a bd 5d 77 8c 8b c7 99 18
    -----END TICKET HEXDUMP-----
    
    -----BEGIN KEYDATA HEXDUMP-----
    63 81 b7 30 81 b4 a0 04 03 02 00 00 a1 2b 30 29
    a0 03 02 01 12 a1 22 04 20 fb 52 ce 29 b4 82 92
    78 a3 ce db 8c a8 7c 0d 13 dc 92 37 d5 10 1f 3d
    9c d2 7f b5 b4 0a 96 8c d1 a2 0b 1b 09 41 52 50
    41 32 2e 4e 45 54 a3 11 30 0f a0 03 02 01 01 a1
    08 30 06 1b 04 72 69 63 6b a4 0b 30 09 a0 03 02
    01 ff a1 02 04 00 a5 1a 18 18 54 75 65 20 53 65
    70 20 32 30 20 31 38 3a 31 32 3a 32 32 20 32 30
    31 36 a6 1a 18 18 54 75 65 20 53 65 70 20 32 30
    20 31 38 3a 31 33 3a 34 31 20 32 30 31 36 a7 1a
    18 18 54 75 65 20 53 65 70 20 32 30 20 31 38 3a
    32 37 3a 32 30 20 32 30 31 36
    -----END KEYDATA HEXDUMP-----
    
    Lengths: plaintext 186, encrypted 233, diff 47
    
    -----BEGIN ENCRYPTED KEYDATA HEXDUMP-----
    30 81 e6 a0 03 02 01 12 a1 03 02 01 02 a2 81 d9
    04 81 d6 9c e5 6e 8e 0f 60 72 ff 14 50 f6 cf a2
    bc d2 81 98 a4 2a c6 0f e4 1d 82 5a c4 66 44 a1
    e1 0b df f4 e7 dc 69 3d 6f 72 4c d7 8b e6 fa 9a
    b1 23 96 3d e3 3f 1c 9e f8 04 16 28 81 fd c1 d0
    93 a2 94 45 f6 3c 4c ed 1f e7 50 db 98 f9 7d a7
    f8 4b 65 72 cf 2d c4 a3 06 e7 70 a4 82 c7 33 e0
    20 7a 81 25 4a ca e6 66 c9 8e 4b 6e ea 53 2a d5
    e1 f3 e0 68 33 e8 cf 35 ad af 4e 7f 1f 20 98 26
    dc c7 b3 55 5c c9 e5 96 b4 40 db 1d e8 f4 8e 2a
    f0 d1 dd 70 47 53 3c f7 30 5c ef 1f bf 2d 07 3f
    3f 6d 40 6f 89 d1 29 0e 26 33 a3 47 ce 4e ac 66
    c6 55 78 32 14 75 1e 9d df 05 75 7f 87 40 82 54
    76 7e 81 c8 38 0b 23 d8 86 97 50 f1 92 4f 7f 3e
    4c c3 89 46 da ee 56 98 a9
    -----END ENCRYPTED KEYDATA HEXDUMP-----
    
    -----BEGIN NDEF HEXDUMP-----
    83 15 00 00 01 50 61 72 70 61 32 2e 6f 72 67 3a
    6b 72 62 35 3a 74 69 63 6b 65 74 61 82 01 4c 30
    82 01 48 a0 03 02 01 05 a1 0b 1b 09 41 52 50 41
    32 2e 4e 45 54 a2 21 30 1f a0 03 02 01 01 a1 18
    30 16 1b 04 78 6d 70 70 1b 0e 78 6d 70 70 2e 61
    72 70 61 32 2e 6e 65 74 a3 82 01 0f 30 82 01 0b
    a0 03 02 01 12 a1 03 02 01 03 a2 81 fe 04 81 fb
    54 18 21 4d 18 f2 cf 8b 4c b7 7e fe 75 a3 98 c2
    2c 36 9c d3 8a d9 e2 6a f6 43 0c 09 43 2c 06 86
    c7 bf 47 68 24 50 d0 66 5b 4e bd 01 2f b2 0c f7
    67 7a 3e 9a 95 0f ef d6 37 61 20 aa a0 1b 36 6c
    a0 68 75 9e 4e b5 00 68 37 ed 98 d5 f7 9a 38 84
    23 71 85 52 42 c5 11 c0 52 b2 9a 94 4b 77 31 fa
    9e 03 bd 78 53 01 a4 9f 81 d4 35 00 06 88 6b 1b
    92 3c 56 ef 15 45 6a 2f 51 f8 79 07 d9 bc 6e 50
    4e 82 17 39 fe 20 d7 93 52 78 c5 3f b8 b3 6e 17
    63 d4 b2 00 cc 21 bf 8e 19 ed 1e 0c 97 26 a5 6b
    e9 53 13 db 07 54 d0 1e bd d3 b4 86 f9 24 22 9f
    ca 22 3e 4c 8d ee e0 dc d6 f1 9b 11 c5 8d 16 ae
    ab ab b2 b8 0b 4d a2 b9 95 98 c4 9c 60 e3 de f7
    4e fb 53 62 16 2b 6a 05 65 85 65 07 bd 91 c8 47
    63 1e 9e 7f 3c cc ed f7 fb 7e cb d3 4a 2f 68 10
    c0 7d 5a bd 5d 77 8c 8b c7 99 18 53 23 e9 61 72
    70 61 32 2e 6f 72 67 3a 6b 72 62 35 3a 65 6e 63
    74 69 63 6b 65 74 70 61 72 74 3a 6b 65 79 74 61
    62 30 81 e6 a0 03 02 01 12 a1 03 02 01 02 a2 81
    d9 04 81 d6 9c e5 6e 8e 0f 60 72 ff 14 50 f6 cf
    a2 bc d2 81 98 a4 2a c6 0f e4 1d 82 5a c4 66 44
    a1 e1 0b df f4 e7 dc 69 3d 6f 72 4c d7 8b e6 fa
    9a b1 23 96 3d e3 3f 1c 9e f8 04 16 28 81 fd c1
    d0 93 a2 94 45 f6 3c 4c ed 1f e7 50 db 98 f9 7d
    a7 f8 4b 65 72 cf 2d c4 a3 06 e7 70 a4 82 c7 33
    e0 20 7a 81 25 4a ca e6 66 c9 8e 4b 6e ea 53 2a
    d5 e1 f3 e0 68 33 e8 cf 35 ad af 4e 7f 1f 20 98
    26 dc c7 b3 55 5c c9 e5 96 b4 40 db 1d e8 f4 8e
    2a f0 d1 dd 70 47 53 3c f7 30 5c ef 1f bf 2d 07
    3f 3f 6d 40 6f 89 d1 29 0e 26 33 a3 47 ce 4e ac
    66 c6 55 78 32 14 75 1e 9d df 05 75 7f 87 40 82
    54 76 7e 81 c8 38 0b 23 d8 86 97 50 f1 92 4f 7f
    3e 4c c3 89 46 da ee 56 98 a9
    -----END NDEF HEXDUMP-----

After this has happened, we have an extra service ticket, needed to
fulfil the requested service; this is the exported service ticket:

    shell$ klist

    Ticket cache: FILE:/tmp/krb5cc_0
    Default principal: rick@ARPA2.NET
    
    Valid starting     Expires            Service principal
    20/09/16 18:12:22  20/09/16 18:27:20  krbtgt/ARPA2.NET@ARPA2.NET
    20/09/16 18:13:41  20/09/16 18:27:20  xmpp/xmpp.arpa2.net@ARPA2.NET

You can pickup the `KEYDATA` to see its contents (including a key!) with

    shell$ hexin /tmp/keydata.der
    00000000> 63 81 b7 30 81 b4 a0 04 03 02 00 00 a1 2b 30 29
    00000010> a0 03 02 01 12 a1 22 04 20 fb 52 ce 29 b4 82 92
    00000020> 78 a3 ce db 8c a8 7c 0d 13 dc 92 37 d5 10 1f 3d
    00000030> 9c d2 7f b5 b4 0a 96 8c d1 a2 0b 1b 09 41 52 50
    00000040> 41 32 2e 4e 45 54 a3 11 30 0f a0 03 02 01 01 a1
    00000050> 08 30 06 1b 04 72 69 63 6b a4 0b 30 09 a0 03 02
    00000060> 01 ff a1 02 04 00 a5 1a 18 18 54 75 65 20 53 65
    00000070> 70 20 32 30 20 31 38 3a 31 32 3a 32 32 20 32 30
    00000080> 31 36 a6 1a 18 18 54 75 65 20 53 65 70 20 32 30
    00000090> 20 31 38 3a 31 33 3a 34 31 20 32 30 31 36 a7 1a
    000000a0> 18 18 54 75 65 20 53 65 70 20 32 30 20 31 38 3a
    000000b0> 32 37 3a 32 30 20 32 30 31 36
    000000ba> ^D

Note how this dump follows the ASN.1 specs, thanks to the Quick DER library:

   EncryptedData   ::= SEQUENCE {
           etype   [0] Int32 -- EncryptionType --,
           kvno    [1] UInt32 OPTIONAL,
           cipher  [2] OCTET STRING -- ciphertext
   }

There is no authorization-data in the ticket cache, so it is absent; there may
be client address data (caddr) in the ticket, not shown in this dump but it
has been shown to work.  Not sure if it's useful if your purpose is to carry
your Kerberos ticket in an NFC Tag to your mobile platform, though.

Next, we can map the NDEF to a binary form and test it in a rudimentary
way with a simple Python script which, somewhat importantly, imports an
external ndef library for Python that has already been tested thoroughtly:

    shell$ hexin > /tmp/tag.ndef
    00000000> 83 15 00 00 01 50 61 72 70 61 32 2e 6f 72 67 3a
    00000010> 6b 72 62 35 3a 74 69 63 6b 65 74 61 82 01 4c 30
    00000020> 82 01 48 a0 03 02 01 05 a1 0b 1b 09 41 52 50 41
    00000030> 32 2e 4e 45 54 a2 21 30 1f a0 03 02 01 01 a1 18
    00000040> 30 16 1b 04 78 6d 70 70 1b 0e 78 6d 70 70 2e 61
    00000050> 72 70 61 32 2e 6e 65 74 a3 82 01 0f 30 82 01 0b
    00000060> a0 03 02 01 12 a1 03 02 01 03 a2 81 fe 04 81 fb
    00000070> 54 18 21 4d 18 f2 cf 8b 4c b7 7e fe 75 a3 98 c2
    00000080> 2c 36 9c d3 8a d9 e2 6a f6 43 0c 09 43 2c 06 86
    00000090> c7 bf 47 68 24 50 d0 66 5b 4e bd 01 2f b2 0c f7
    000000a0> 67 7a 3e 9a 95 0f ef d6 37 61 20 aa a0 1b 36 6c
    000000b0> a0 68 75 9e 4e b5 00 68 37 ed 98 d5 f7 9a 38 84
    000000c0> 23 71 85 52 42 c5 11 c0 52 b2 9a 94 4b 77 31 fa
    000000d0> 9e 03 bd 78 53 01 a4 9f 81 d4 35 00 06 88 6b 1b
    000000e0> 92 3c 56 ef 15 45 6a 2f 51 f8 79 07 d9 bc 6e 50
    000000f0> 4e 82 17 39 fe 20 d7 93 52 78 c5 3f b8 b3 6e 17
    00000100> 63 d4 b2 00 cc 21 bf 8e 19 ed 1e 0c 97 26 a5 6b
    00000110> e9 53 13 db 07 54 d0 1e bd d3 b4 86 f9 24 22 9f
    00000120> ca 22 3e 4c 8d ee e0 dc d6 f1 9b 11 c5 8d 16 ae
    00000130> ab ab b2 b8 0b 4d a2 b9 95 98 c4 9c 60 e3 de f7
    00000140> 4e fb 53 62 16 2b 6a 05 65 85 65 07 bd 91 c8 47
    00000150> 63 1e 9e 7f 3c cc ed f7 fb 7e cb d3 4a 2f 68 10
    00000160> c0 7d 5a bd 5d 77 8c 8b c7 99 18 53 23 e9 61 72
    00000170> 70 61 32 2e 6f 72 67 3a 6b 72 62 35 3a 65 6e 63
    00000180> 74 69 63 6b 65 74 70 61 72 74 3a 6b 65 79 74 61
    00000190> 62 30 81 e6 a0 03 02 01 12 a1 03 02 01 02 a2 81
    000001a0> d9 04 81 d6 9c e5 6e 8e 0f 60 72 ff 14 50 f6 cf
    000001b0> a2 bc d2 81 98 a4 2a c6 0f e4 1d 82 5a c4 66 44
    000001c0> a1 e1 0b df f4 e7 dc 69 3d 6f 72 4c d7 8b e6 fa
    000001d0> 9a b1 23 96 3d e3 3f 1c 9e f8 04 16 28 81 fd c1
    000001e0> d0 93 a2 94 45 f6 3c 4c ed 1f e7 50 db 98 f9 7d
    000001f0> a7 f8 4b 65 72 cf 2d c4 a3 06 e7 70 a4 82 c7 33
    00000200> e0 20 7a 81 25 4a ca e6 66 c9 8e 4b 6e ea 53 2a
    00000210> d5 e1 f3 e0 68 33 e8 cf 35 ad af 4e 7f 1f 20 98
    00000220> 26 dc c7 b3 55 5c c9 e5 96 b4 40 db 1d e8 f4 8e
    00000230> 2a f0 d1 dd 70 47 53 3c f7 30 5c ef 1f bf 2d 07
    00000240> 3f 3f 6d 40 6f 89 d1 29 0e 26 33 a3 47 ce 4e ac
    00000250> 66 c6 55 78 32 14 75 1e 9d df 05 75 7f 87 40 82
    00000260> 54 76 7e 81 c8 38 0b 23 d8 86 97 50 f1 92 4f 7f
    00000270> 3e 4c c3 89 46 da ee 56 98 a9
    0000027a>

Then we can pass the binary NDEF file in `/tmp/tag.ndef` into the test script
that implements special type support for the URI types that we introduced
here, and that it does indeed recognise:

    shell$ ./test-ndef.py /tmp/tag.ndef
    Record length 336 and type <class '__main__.KerberosTicket'>
    Record length 233 and type <class '__main__.KerberosEncTicketPartKeytab'>

Finally, quite important as well, we should know how many bytes we have
consumed...

    shell$ ls -l /tmp/tag.ndef
    -rw-r--r-- 1 user user 634 Sep 20 18:26 /tmp/tag.ndef

This fits well within large static tags we found to be popular and widely
produced, namely those based on the NTAG 216 chip.  We would not be
surprised if future development moves towards larger chips as well.

