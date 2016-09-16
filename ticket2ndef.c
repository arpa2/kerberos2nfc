/*
 * ticket2ndef.c -- Fetch a service ticket and produce an NDEF file for NFC.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <krb5.h>

#include <quick-der/api.h>
#include <quick-der/rfc4120.h>


/* The packaging description for a Ticket, used for one record type */
const derwalk ticket_record [] = {
	DER_PACK_rfc4120_Ticket,
	DER_PACK_END
};

/* The packaging description for a EncTicketPart, used before encrypting
 * into the record type that is intended for a particular recipient.
 */
const derwalk ticket_encticketpart [] = {
	DER_PACK_rfc4120_EncTicketPart,
	DER_PACK_END
};

/* The packaging description for a KerberosString, used for components in
 * the PrincipalName.
 */
const derwalk ticket_kerberosstring [] = {
	DER_PACK_rfc4120_KerberosString,
	DER_PACK_END
};

/* The packaging description for a HostAddress, used in a SEQUENCE OF and
 * thus packed separately.
 */
const derwalk ticket_hostaddress [] = {
	DER_PACK_rfc4120_HostAddress,
	DER_PACK_END
};

/* An empty SEQUENCE, used for the TransitedEncoding (at least for now).
 */
dercursor der_empty_sequence = {
	.derlen = 2,
	.derptr = "\x03\x00",
};


#if 0
/* DER utility: This should probably appear in Quick DER sometime soon.
 *
 * Pack a DER header with a given tag and length, but not the contents.
 * This can be used to easily insert structure for use with der_prepack()
 * if the total length of DER to be added is known.
 *
 * The routine places a reasonable upper limit to the acceptable lengths,
 * and the buffer structure offers the corresponding size.
 */
typedef uint8_t QDERBUF_HEADER_T [4];
dercursor qder2b_pack_header (uint8_t *target_4b, uint8_t tag, size_t length) {
	dercursor retval;
	retval.derptr = target_4b;
	assert (length <= 65535);
	*target_4b++ = tag;
	if (length > 127) {
		*target_4b++ = 2;
		*target_4b++ = (length >> 8) & 0xff;
		*target_4b++ = (length     ) & 0xff;
		retval.derlen = 4;
	} else {
		*target_4b++ = (length     ) & 0xff;
		retval.derlen = 4;
	}
	return retval;
}
#endif


/* DER utility: This should probably appear in Quick DER sometime soon.
 *
 * Pack an Int32 or UInt32 and return the number of bytes.  Do not pack a header
 * around it.  The function returns the number of bytes taken, even 0 is valid.
 */
typedef uint8_t QDERBUF_INT32_T [4];
dercursor qder2b_pack_int32 (uint8_t *target_4b, int32_t value) {
	dercursor retval;
	int shift = 24;
	retval.derptr = target_4b;
	retval.derlen = 0;
	while (shift >= 0) {
		if ((retval.derlen == 0) && (shift > 0)) {
			// Skip sign-extending initial bytes
			uint32_t neutro = (value >> (shift - 1) ) & 0x000001ff;
			if ((neutro == 0x000001ff) || (neutro == 0x00000000)) {
				shift -= 8;
				continue;
			}
		}
		target_4b [retval.derlen] = (value >> shift) & 0xff;
		retval.derlen++;
		shift -= 8;
	}
	return retval;
}
typedef uint8_t QDERBUF_UINT32_T [5];
dercursor qder2b_pack_uint32 (uint8_t *target_5b, uint32_t value) {
	dercursor retval;
	int ofs = 0;
	if (value & 0x80000000) {
		*target_5b = 0x00;
		ofs = 1;
	}
	retval = qder2b_pack_int32 (target_5b + ofs, (int32_t) value);
	retval.derptr -= ofs;
	retval.derlen += ofs;
	return retval;
}


/* DER utility: This should probably appear in Quick DER sometime soon.
 *
 * Unpack an Int32 or UInt32 from a given number of bytes.  Do not assume a header
 * around it.  The function returns the value found.
 *
 * Out of range values are returned as 0.  This value only indicates invalid
 * return when len > 1, so check for that.
 */
int32_t qder2b_unpack_int32 (dercursor data4) {
	int32_t retval = 0;
	int idx;
	if (data4.derlen > 4) {
		goto done;
	}
	if ((data4.derlen > 0) && (0x80 & *data4.derptr)) {
		retval = -1;
	}
	for (idx=0; idx<data4.derlen; idx++) {
		retval <<= 8;
		retval += data4.derptr [idx];
	}
done:
	return retval;
}
uint32_t qder2b_unpack_uint32 (dercursor data5) {
	uint32_t retval = 0;
	int ofs = 0;
	if (data5.derlen > 5) {
		goto done;
	}
	if (data5.derlen == 5) {
		if (*data5.derptr != 0x00) {
			goto done;
		}
		// Modify the local copy on our stack
		data5.derlen--;
		data5.derptr++;
	}
	retval = (uint32_t) qder2b_unpack_int32 (data5);
done:
	return retval;
}


/* Find a ticket in the credentials cache
 */
krb5_error_code find_ticket (krb5_context ctx, krb5_ccache cache, char *servicename, krb5_creds **ticket) {
	krb5_error_code kerrno = 0;
	krb5_principal cli;
	int have_cli = 0;
	krb5_principal svc;
	int have_svc = 0;
	krb5_creds match;
	int have_ticket = 0;
	int i;

	//
	// Get the default principal describing the client
	if (!kerrno) {
		kerrno = krb5_cc_get_principal (ctx, cache, &cli);
		have_cli = (kerrno == 0);
	}

	//
	// Possibly build a default principal for the service
	if (!kerrno) {
		if (servicename != NULL) {
			kerrno = krb5_parse_name (ctx, servicename, &svc);
		} else {
			kerrno = krb5_build_principal_ext (ctx, &svc, 
				cli->realm.length, cli->realm.data,
				6, "krbtgt",
				cli->realm.length, cli->realm.data,
				0 /* end marker */ );
		}
		have_svc = (kerrno == 0);
	}

	//
	// Retrieve a ticket for (cli,svc)
	if (!kerrno) {
		memset (&match, 0, sizeof (match));
		match.magic = 0; /*TODO*/
		match.client = cli;
		match.server = svc;
		// kerrno = krb5_cc_retrieve_cred (ctx, cache, 0, &match, ticket);
		kerrno = krb5_get_credentials (ctx, 0, cache, &match, ticket);
		have_ticket = (kerrno == 0);
	}
	if (!kerrno) {
		//TODO// kerrno = krb5int_validate_times (ctx, (*ticket)->times);
		//TODO// use KRB5_TC_MATCH_TIMES to enforce match's lifetimes
	}

	//
	// Print ticket descriptive information
	if (have_cli) {
		printf ("-----BEGIN CLIENT PRINCIPAL-----\n");
		printf ("NameType: %d\n", cli->type);
		for (i=0; i<cli->length; i++) {
			printf ("Name_%d: %.*s\n", i, cli->data [i].length, cli->data [i].data);
		}
		printf ("Realm: %.*s\n", svc->realm.length, svc->realm.data);
		printf ("-----END CLIENT PRINCIPAL-----\n");
	}
	printf ("\n");
	if (have_svc) {
		printf ("-----BEGIN SERVICE PRINCIPAL-----\n");
		printf ("NameType: %d\n", svc->type);
		for (i=0; i<svc->length; i++) {
			printf ("Name_%d: %.*s\n", i, svc->data [i].length, svc->data [i].data);
		}
		printf ("Realm: %.*s\n", svc->realm.length, svc->realm.data);
		printf ("-----END SERVICE PRINCIPAL-----\n");
	}
	printf ("\n");
	if (have_ticket) {
		printf ("-----BEGIN TICKET HEXDUMP-----\n");
		i = 0;
		while (i < (*ticket)->ticket.length) {
			char sep = (((i & 15) != 15) && (i != (*ticket)->ticket.length - 1))? ' ': '\n';
			printf ("%02x%c", (uint8_t) (*ticket)->ticket.data [i++], sep);
		}
		printf ("-----END TICKET HEXDUMP-----\n");
	}

	//
	// Cleanup
	if (kerrno && have_ticket) {
		krb5_free_cred_contents (ctx, *ticket);
		*ticket = NULL;
		have_ticket = 0;
	}
	if (have_svc) {
		krb5_free_principal (ctx, svc);
		have_svc = 0;
	}
	if (have_cli) {
		krb5_free_principal (ctx, cli);
		have_cli = 0;
	}

	//
	// Return the overall result
	return kerrno;
}


/* Construct the EncTicketPart from a krb5_creds structure.  This will serve
 * as a release mechanism for key data towards selected recipients, such as
 * a mobile device.  To actually release that data, what is produced here
 * must be encrypted to those recipients and, perhaps, embellished with
 * some selecting criteria.
 *
 * The keydata will be allocated in this function, and when it is returned
 * non-NULL, the caller must clean it up with malloc().
 */
krb5_error_code make_keydata (krb5_context ctx, krb5_creds *crd, uint8_t **keydata) {
	DER_OVLY_rfc4120_EncTicketPart kdcrs;
	krb5_error_code kerrno = 0;
	int numhostaddr = 0;
	int numcnamecompo = 0;
	dercursor *cleanup_hostaddr = NULL;
	dercursor *cleanup_cnamecompo = NULL;
	int i;
	//
	// Sanity checks & Initialisation
	*keydata = NULL;
	memset (&kdcrs, 0, sizeof (kdcrs));
	//
	// Fill the various cursors in kdcrs that we intend to generate
	QDERBUF_INT32_T derflaghack;	// MIT Kerberos uses signed int32 :'-(
	kdcrs.flags = qder2b_pack_int32 (derflaghack, crd->ticket_flags);
	assert (kdcrs.flags.derlen >= 2);
	kdcrs.flags.derlen -= 2;	// Hack away the tag and length
	kdcrs.flags.derptr += 2;	// Be left with BIT STRING input
	QDERBUF_INT32_T derkeytp;
	kdcrs.key.keytype = qder2b_pack_int32 (derkeytp, crd->keyblock.enctype);
	kdcrs.key.keyvalue.derlen = crd->keyblock.length;
	kdcrs.key.keyvalue.derptr = crd->keyblock.contents;
	kdcrs.crealm.derlen = crd->client->realm.length;
	kdcrs.crealm.derptr = crd->client->realm.data;
	QDERBUF_INT32_T derclinametp;
	kdcrs.cname.name_type = qder2b_pack_int32 (derclinametp, crd->client->type);
	numcnamecompo = crd->client->length;
	dercursor cnamecompo [numcnamecompo];
	memset (cnamecompo, 0, sizeof (cnamecompo));
	cleanup_cnamecompo = cnamecompo;
	numhostaddr = 0;
	if (crd->addresses != NULL) {
		while (crd->addresses [numhostaddr] != NULL) {
			numhostaddr++;
		}
	}
	dercursor hostaddrs [numhostaddr];
	memset (hostaddrs, 0, sizeof (hostaddrs));
	cleanup_hostaddr = hostaddrs;
	i = numcnamecompo;
	while (i-- > 0) {
		dercursor compo;
		compo.derlen = crd->client->data [i].length;
		compo.derptr = crd->client->data [i].data;
		cnamecompo [i].derlen = der_pack (ticket_kerberosstring,
				(dercursor *) &compo,
				NULL);
		cnamecompo [i].derptr = malloc (cnamecompo [i].derlen);
		if (cnamecompo [i].derptr == NULL) {
			kerrno = ENOMEM;
			goto cleanup;
		}
		assert (cnamecompo [i].derlen == der_pack (ticket_kerberosstring,
				(dercursor *) &compo,
				cnamecompo [i].derptr + cnamecompo [i].derlen));
	}
	der_prepack (cnamecompo, numcnamecompo,
			(derarray *) &kdcrs.cname.name_string);
	fprintf (stderr, "TODO: Sending mere place-holder for TransitedEncoding\n");
	QDERBUF_INT32_T dertrtype;
	kdcrs.transited.tr_type = qder2b_pack_int32 (dertrtype, -1);
	kdcrs.transited.contents.derlen = 0;
	kdcrs.transited.contents.derptr = "";
	char derauthtime [100];
	krb5_timestamp_to_string (crd->times.authtime,
					derauthtime, sizeof (derauthtime));
	derauthtime [sizeof (derauthtime)-1] = '\0';
	kdcrs.authtime.derlen = strlen (derauthtime);
	kdcrs.authtime.derptr = derauthtime;
	//TODO// starttime OPTIONAL
	char derstarttime [100];
	if (crd->times.starttime > crd->times.authtime) {
		krb5_timestamp_to_string (crd->times.starttime,
					derstarttime, sizeof (derstarttime));
		derstarttime [sizeof (derstarttime)-1] = '\0';
		kdcrs.starttime.derlen = strlen (derstarttime);
		kdcrs.starttime.derptr = derstarttime;
	}
	char derendtime [100];
	krb5_timestamp_to_string (crd->times.endtime,
					derendtime, sizeof (derendtime));
	derendtime [sizeof (derendtime)-1] = '\0';
	kdcrs.endtime.derlen = strlen (derendtime);
	kdcrs.endtime.derptr = derendtime;
	char dertilltime [100];
	if (crd->times.renew_till > crd->times.starttime) {
		krb5_timestamp_to_string (crd->times.renew_till,
					dertilltime, sizeof (dertilltime));
		dertilltime [sizeof(dertilltime)-1] = '\0';
		kdcrs.renew_till.derlen = strlen (dertilltime);
		kdcrs.renew_till.derptr = dertilltime;
	}
	i = numhostaddr;
	while (i-- > 0) {
		DER_OVLY_rfc4120_HostAddress had;
		QDERBUF_INT32_T hat;
		had.addr_type = qder2b_pack_int32 (
				hat,
				crd->addresses [i]->addrtype);
		had.address.derlen = crd->addresses [i]->length;
		had.address.derptr = crd->addresses [i]->contents;
		hostaddrs [i].derlen = der_pack (
				ticket_hostaddress,
				(dercursor *) &had,
				NULL);
		hostaddrs [i].derptr = malloc (hostaddrs [i].derlen);
		if (hostaddrs [i].derptr == NULL) {
			kerrno = ENOMEM;
			goto cleanup;
		}
		assert (hostaddrs [i].derlen == der_pack (
				ticket_hostaddress,
				(dercursor *) &had,
				hostaddrs [i].derptr + hostaddrs [i].derlen));
	}
	//INSUFFICIENT// if (crd->addresses != NULL)
	if (numhostaddr > 0) {
		// Strangely, empty lists seem to exist, yet grant all host addrs?
		der_prepack (hostaddrs, numhostaddr,
			(derarray *) &kdcrs.caddr);
	}
	// authorization_data is absent; it is neither in AS-REP nor TGS-REP
	//
	// Find the length of the DER data, once it is packed, and allocate it
	size_t keydatalen = der_pack (ticket_encticketpart,
					(dercursor *) &kdcrs,
					NULL);
	*keydata = malloc (keydatalen);
	if (*keydata == NULL) {
		return ENOMEM;
	}
	//
	// Pack de DER data into the provisioned length
	assert (keydatalen == der_pack (ticket_encticketpart,
					(dercursor *) &kdcrs,
					*keydata + keydatalen));
	//
	// Dump the packed data on the screen
	printf ("-----BEGIN KEYDATA HEXDUMP-----\n");
	i = 0;
	while (i < keydatalen) {
		char sep = (((i & 15) != 15) && (i != keydatalen - 1))? ' ': '\n';
		printf ("%02x%c", (uint8_t) (*keydata) [i++], sep);
	}
	printf ("-----END KEYDATA HEXDUMP-----\n");
	//
	// Cleanup and return kerrno
cleanup:
	if (cleanup_cnamecompo != NULL) {
		for (i=0; i<numcnamecompo; i++) {
			free (cleanup_cnamecompo [i].derptr);
			cleanup_cnamecompo [i].derptr = NULL;
		}
	}
	if (cleanup_hostaddr != NULL) {
		for (i=0; i<numhostaddr; i++) {
			free (cleanup_hostaddr [i].derptr);
			cleanup_hostaddr [i].derptr = NULL;
		}
	}
	return kerrno;
}


/* Main routine
 */
int main (int argc, char *argv []) {
	krb5_error_code kerrno = 0;
	krb5_context ctx;
	int have_ctx = 0;
	krb5_ccache cache;
	int have_cache = 0;
	krb5_creds *ticket = NULL;
	uint8_t *encdata = NULL;
	int have_ticket = 0;
	int have_encdata = 0;
	krb5_data *x509;
	int have_x509 = 0;
	char *servicename = NULL;

	//
	// Parse commandline
	if (argc > 2) {
		fprintf (stderr, "Usage: %s [servicename]\n", argv [0]);
		exit (1);
	} else if (argc == 2) {
		servicename = argv [1];
	}

	//
	// Allocate and Initialise resources
	if (!kerrno) {
		kerrno = krb5_init_context (&ctx);
		have_ctx = (kerrno == 0);
	}
	if (!kerrno) {
		kerrno = krb5_cc_default (ctx, &cache);
		have_cache = (kerrno == 0);
	}

	//
	// Obtain a ticket
	if (!kerrno) {
		kerrno = find_ticket (ctx, cache, servicename, &ticket);
		have_ticket = (kerrno == 0);
	}

	//
	// Construct EncTicketData from the fields in the Ticket found
	if (!kerrno) {
		assert (have_ticket);
		kerrno = make_keydata (ctx, ticket, &encdata);
		have_encdata = (kerrno == 0);
	}

	//
	// Error reporting and Cleanup
	if (kerrno) {
		const char *errmsg = krb5_get_error_message (ctx, kerrno);
		fprintf (stderr, "Error in Kerberos: %s\n", errmsg);
		krb5_free_error_message (ctx, errmsg);
	}
	if (have_encdata) {
		free (encdata);
		encdata = NULL;
		have_encdata = 0;
	}
	if (have_ticket) {
		krb5_free_creds (ctx, ticket);
		ticket = NULL;
		have_ticket = 0;
	}
	if (have_cache) {
		krb5_cc_close (ctx, cache);
		have_cache = 0;
	}
	if (have_ctx) {
		krb5_free_context (ctx);
		have_ctx = 0;
	}

	//
	// Exit with the krb5_error_code (0 for success)
	exit (kerrno);
}

