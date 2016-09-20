# Kerberos tools for NFC

> *These tools are used to extract a Ticket and stick it on an NFC Tag.
> That sounds silly, but it really is a pragmatic (and secure) manner
> of distributing credentials from a well-protected home/office desktop
> to a more hostile mobile environment.  It can be an easily understood
> user interface action to swipe an NFC Tag again, to reinforce or renew
> a credential or renew it, or to switch identity.*

**See also:** [Beaming Credentials to Kerberos](http://nfc.arpa2.net/kerb-ticks.html)

An NFC Tag can store about 888 bytes (in the case of an NTAG216) of user
data.  If this data is an NDEF file, then typed blobs can be listed in
so-called records.

For use with Kerberos, we define a record for a `Ticket` and another for
the encrypted data holding an `EncTicketPart` encrypted in a way that
the recipient could decode somehow.  And that really is "somehow", in that
it might use any algorithm or key system that makes sense on the recipient,
and it may even mingle a fixed on-device key with a user-entered PIN.

There can be multiple of each, but for a tag that is currently only
a theory; a `Ticket` is about 350 bytes and the encrypted `EncTicketData`
is easily 275 bytes long, so there is room for some metadata but there
cannot be multiple instances of the two elements.  Not on a simple NFC Tag
at least.

Still, these two suffice for import into a mobile environment, and they
provide tickets to continue to work.  When the ticket is a TGT, it is
possible to derive service tickets, but it is just as possible that only
a service ticket is passed over the NFC Tag; this is all a matter of choice.
Or, a realm-crossover TGT could be somewhere in between.

## Ticket to NDEF

To produce the records, call

    ticket2ndef service/host.name@MYREALM

or if the current user's TGT suffices, then instead call

    ticket2ndef

In both cases, the output shows the NDEF information (in hex, plus it will dump
a lot more).  The NDEF information holds the two records for the `Ticket` and
adjoining `EncTicketData`, the latter of which is encrypted to (TODO).

If you passed the NDEF data to an NFC utility that operates a reader/writer,
you can program it into any sufficiently large NFC Tag.  The resulting tag
passes the information to the mobile environment, where it may be picked up
by a suitable NFC tool, and inserted into the local Kerberos setup.  The
decryption action to find the `EncTicketData` would require decryption,
hopefully based on a stored secret.  Since a `Ticket` has only a limited
lifetime, such a secret may be fixed, but is still not a real threat, as
long as it cannot be easily guessed &mdash; so four-digit PIN codes are
off the menu.  A cryptographic mixture of a four-digit PIN and some
internally stored, phone-specific secret may however work well without
harming the end-user experience.

## Required Software and Hardware

The following bits of software are used here:

  * [Quick DER](https://github.com/vanrein/quick-der) for encoding/decoding DER structures defined in the [RFC4120](https://tools.ietf.org/html/rfc4120) header file
  * [libkrb5](http://web.mit.edu/kerberos/krb5-current/doc/appdev/refs/index.html) to interface to your MIT Kerberos credentials cache
  * [hexio](https://github.com/vanrein/hexio) provides tools for the [demorun](demorun.txt): `hexin`, `derdump`
  * Optional: [nfcpy/ndeflib](https://github.com/nfcpy/ndeflib) to test the NDEF  output

To use it completely, you will also need some hardware and drivers:

  * An NFC reader/writer; perhaps your smart phone or a [PN532 module](https://www.aliexpress.com/wholesale?catId=0&initiative_id=SB_20160915080103&SearchText=pn532+module)
  * Tools to exchange NDEF objects with your NFC reader/writer; perhaps [nfcpy](https://github.com/nfcpy/nfcpy)
  * Suitable NFC Tags; perhaps based on [NTAG216](http://www.nxp.com/products/identification-and-security/smart-label-and-tag-ics/ntag/nfc-forum-type-2-tag-compliant-ic-with-144-504-888-bytes-user-memory:NTAG213_215_216?)

To make the Kerberos tickets actually import to your smart phone, you should
find a suitable App to read NFC Tags, and process Kerberos records in its
NDEF object.  You are also going to need a
[Kerberos port to Android](https://github.com/cconlon/kerberos-android-ndk)
and applications that actually use it for authentication purposes.

Please understand that a bit more needs to be done before the whole thing
can fly; this project is merely one stepping stone.

