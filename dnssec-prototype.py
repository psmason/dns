#!/usr/bin/env python3

import dnslib
import ecdsa
import hashlib
import socket

def query_nameserver(question, name_server_address):
    query = dnslib.DNSRecord(q=question)
    # Disabling the recursion desired bit, so that this toy project
    # handles recursion requirements.
    query.header.set_rd(False)

    # Using EDNS0, set the DNSSEC OK bit. 
    # See https://www.rfc-editor.org/rfc/rfc3225 for how this works. 
    query.add_ar(dnslib.EDNS0(flags="do"))

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Binding to port zero allows the os to choose an available port
    client_socket.bind(('', 0))        
    client_socket.sendto(query.pack(), (name_server_address, 53))
    raw_response, _ = client_socket.recvfrom(1024)
    parsed_response = dnslib.DNSRecord.parse(raw_response)
    print("received name server response:", parsed_response)
    return parsed_response

def fetch_dnskeys(name_server_address):
    response = query_nameserver(dnslib.DNSQuestion("example.com.", dnslib.QTYPE.DNSKEY), name_server_address)
    if response.get_a().rtype != dnslib.QTYPE.DNSKEY:
        raise Exception("expected answer of type DNSKEY")
    rrs = []
    for rr in response.rr:
        if rr.rtype == dnslib.QTYPE.DNSKEY:
            rrs.append(rr)
        elif rr.rtype == dnslib.QTYPE.RRSIG:
            rrsig = rr
    return rrs, rrsig.rdata

def fetch_a_records(name_server_address):
    response = query_nameserver(dnslib.DNSQuestion("example.com.", dnslib.QTYPE.A), name_server_address)
    if response.get_a().rtype != dnslib.QTYPE.A:
        raise Exception("expected answer of type A")
    rrs = []
    for rr in response.rr:
        if rr.rtype == dnslib.QTYPE.A:
            rrs.append(rr)
        elif rr.rtype == dnslib.QTYPE.RRSIG:
            rrsig = rr
    return rrs, rrsig.rdata

def fetch_ds(name_server_address):
    response = query_nameserver(dnslib.DNSQuestion("example.com.", dnslib.QTYPE.DS), name_server_address)
    if response.get_a().rtype != dnslib.QTYPE.DS:
        raise Exception("expected answer of type DS")
    for rr in response.rr:
        if rr.rtype == dnslib.QTYPE.DS:
            return rr.rdata

def get_zone_signing_key(dnskeys):
    for rr in dnskeys:
        # The zone signing key has flag field set to 256.
        # Reference: https://www.rfc-editor.org/rfc/rfc4034#section-2.1.1
        if rr.rdata.flags == 256:
            return rr
        
def get_key_signing_key(dnskeys):
    for rr in dnskeys:
        # The key signing key has flag field set to 257.
        # Reference: https://www.rfc-editor.org/rfc/rfc4034#section-2.1.1
        if rr.rdata.flags == 257:
            return rr
        
def encode_name(name):
    # From https://www.rfc-editor.org/rfc/rfc1035#section-3.1:
    #   Domain names in messages are expressed in terms of a sequence of labels.
    #   Each label is represented as a one octet length field followed by that
    #   number of octets.  Since every domain name ends with the null label of
    #   the root, a domain name is terminated by a length byte of zero.
    data = bytearray()
    for token in name.split('.'):
        data.append(len(token))
        for c in token:
            data.append(ord(c))
    return data

def build_rrsig_signing_data(rrsig):
    # How to build up the data being verified: https://www.rfc-editor.org/rfc/rfc4034#section-3.1.8.1.
    #   signature = sign(RRSIG_RDATA | RR(1) | RR(2)... )where "|" denotes concatenation;
    #
    #   RRSIG_RDATA is the wire format of the RRSIG RDATA fields
    #               with the Signer's Name field in canonical form and
    #               the Signature field excluded;
    #
    # See https://www.rfc-editor.org/rfc/rfc4034#section-3.1 for the wire format 
    # description.
    data = bytearray()
    # Two bytes for types covered
    data.extend(rrsig.covered.to_bytes(length=2, byteorder='big'))
    # One byte for algorithm
    data.extend(rrsig.algorithm.to_bytes(length=1, byteorder='big'))
    # One byte for labels
    data.extend(rrsig.labels.to_bytes(length=1, byteorder='big'))
    # Four bytes for original ttl
    data.extend(rrsig.orig_ttl.to_bytes(length=4, byteorder='big'))
    # Four bytes for signature expiration
    data.extend(rrsig.sig_exp.to_bytes(length=4, byteorder='big'))
    # Four bytes for signature inception
    data.extend(rrsig.sig_inc.to_bytes(length=4, byteorder='big'))
    # Two bytes for the key tags.
    data.extend(rrsig.key_tag.to_bytes(length=2, byteorder='big'))
    # The name in the signature
    data.extend(encode_name(str(rrsig.name)))

    return data

def build_rrs_signing_data(rrs):
    # How to build up the data being verified, continued with resource records.
    #   signature = sign(RRSIG_RDATA | RR(1) | RR(2)... )where "|" denotes concatenation;
    #
    #   RR(i) = owner | type | class | TTL | RDATA length | RDATA
    #
    # See https://www.rfc-editor.org/rfc/rfc1035#section-3.2.1 for the wire format
    # description.
    data = bytearray()

    for rr in rrs:
        data.extend(encode_name(str(rr.rname)))
        data.extend(rr.rtype.to_bytes(length=2, byteorder='big'))
        data.extend(rr.rclass.to_bytes(length=2, byteorder='big'))
        data.extend(rr.ttl.to_bytes(length=4, byteorder='big'))

        if rr.rtype == dnslib.QTYPE.A:
            # TODO: this assumes A record type
            # rdlength doesn't seem to work
            data.extend(int(4).to_bytes(length=2, byteorder='big'))
            for b in rr.rdata.data:
                data.extend(b.to_bytes(length=1, byteorder='big'))
        elif rr.rtype == dnslib.QTYPE.DNSKEY:
            rdata = dnslib.Buffer()
            rr.rdata.pack(rdata)
            # Appending rdlength
            data.extend(int(len(rdata.data)).to_bytes(length=2, byteorder='big'))
            # Appending rdata
            data.extend(rdata.data)
        else:
            raise Exception("Unexpected RR type to sign:", rr.rtype)

    return data

def verify_data(signing_key, rrsig, rrs):
    # https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
    if signing_key.algorithm != 13:
        raise Exception("expected RRSIG algorithm 13: ECDSAP256SHA256")
    if signing_key.protocol != 3:
        # The protocol value must be set to 3.
        # Reference: https://www.rfc-editor.org/rfc/rfc4034#section-2.1.2
        raise Exception("Invalid DNSKEY: protocol not set to 3")
    
    if rrsig.algorithm != 13:
        raise Exception("expected RRSIG algorithm 13: ECDSAP256SHA256")
    
    data = bytearray()
    data.extend(build_rrsig_signing_data(rrsig))
    data.extend(build_rrs_signing_data(rrs))

    # From https://www.rfc-editor.org/rfc/rfc6605.html#section-4:
    #   ECDSA public keys consist of a single value, called "Q" in FIPS
    #   186-3.  In DNSSEC keys, Q is a simple bit string that represents the
    #   uncompressed form of a curve point, "x | y".
    #
    # The key is already base64 decoded by the dnslib library, which is required following
    # https://www.rfc-editor.org/rfc/rfc4034#section-2.2.
    zsk_point = ecdsa.ellipticcurve.Point.from_bytes(curve=ecdsa.NIST256p.curve, data=signing_key.key)
    verifier = ecdsa.VerifyingKey.from_public_point(point=zsk_point, curve=ecdsa.NIST256p)

    # From https://www.rfc-editor.org/rfc/rfc6605.html#section-4:
    #   The two integers, each of which is formatted as a simple octet string, are combined 
    #   into a single longer octet string for DNSSEC as the concatenation "r | s".
    #
    # So let's use the "raw" signature decoder.
    verifier.verify(signature=rrsig.sig, data=data, hashfunc=hashlib.sha256, sigdecode=ecdsa.util.sigdecode_string)
    print("Successfully verified data")

def verify_ds(ds, key_signing_key):
    # https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml
    if ds.digest_type != 2:
        raise Exception("expected DS digest type of 2: SHA256")
    
    # From https://www.rfc-editor.org/rfc/rfc4034.html#section-5.1.4
    #  The digest is calculated by concatenating the canonical form of the
    #  fully qualified owner name of the DNSKEY RR with the DNSKEY RDATA,
    #  and then applying the digest algorithm.
    #
    #  digest = digest_algorithm( DNSKEY owner name | DNSKEY RDATA);
    #
    #  "|" denotes concatenation
    #
    #  DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key.
    data = bytearray()
    data.extend(encode_name(str(key_signing_key.rname)))
    
    dnskey_rdata = dnslib.Buffer()
    key_signing_key.rdata.pack(dnskey_rdata)
    data.extend(dnskey_rdata.data)

    if hashlib.sha256(data).hexdigest() != ds.digest.hex():
        raise Exception("Failed to validate against the parent DS record. SHA256 mismatch!")
    print("Successfully validated against the DS digest")

### Running verification

# Fetching DNSKEYS from a.iana-servers.net.
dnskeys, dnskey_rrsig = fetch_dnskeys("199.43.135.53")

# Verifying zone data
zsk = get_zone_signing_key(dnskeys) 
# Fetching A records from a.iana-servers.net.
rrs, a_rrsig = fetch_a_records("199.43.135.53")
verify_data(zsk.rdata, a_rrsig, rrs)

# Verifying key data
ksk = get_key_signing_key(dnskeys)
verify_data(ksk.rdata, dnskey_rrsig, dnskeys)

# Fetch the parent's DS record, from a.gtld-servers.net.
parent_ds = fetch_ds("192.5.6.30")
verify_ds(parent_ds, ksk)








