#!/usr/bin/env python3

import dnslib
import ecdsa
import hashlib
import socket

def query_nameserver(question):
    query = dnslib.DNSRecord(q=question)
    # Disabling the recursion desired bit, so that this toy project
    # handles recursion requirements.
    query.header.set_rd(False)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Binding to port zero allows the os to choose an available port
    client_socket.bind(('', 0))        

    # a.iana-servers.net.
    client_socket.sendto(query.pack(), ("199.43.135.53", 53))

    raw_response, _ = client_socket.recvfrom(1024)
    parsed_response = dnslib.DNSRecord.parse(raw_response)
    print("received name server response:", parsed_response)
    return parsed_response

def fetch_rrsig():
    response = query_nameserver(dnslib.DNSQuestion("example.com.", dnslib.QTYPE.RRSIG))
    if response.get_a().rtype != dnslib.QTYPE.RRSIG:
        raise Exception("expected answer of type RRSIG")
    return response.get_a().rdata


def fetch_dnskeys():
    response = query_nameserver(dnslib.DNSQuestion("example.com.", dnslib.QTYPE.DNSKEY))
    if response.get_a().rtype != dnslib.QTYPE.DNSKEY:
        raise Exception("expected answer of type DNSKEY")
    return response.rr

def fetch_a_records():
    response = query_nameserver(dnslib.DNSQuestion("example.com.", dnslib.QTYPE.A))
    if response.get_a().rtype != dnslib.QTYPE.A:
        raise Exception("expected answer of type A")
    return response.rr

def get_zone_signing_key(dnskeys):
    for rr in dnskeys:
        # The zone signing key has flag field set to 256.
        # Reference: https://www.rfc-editor.org/rfc/rfc4034#section-2.1.1
        if rr.rdata.flags == 256:
            return rr.rdata
        
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

dnskey = fetch_dnskeys()
zsk = get_zone_signing_key(dnskey) 
if zsk.algorithm != 13:
    raise Exception("expected RRSIG algorithm 13: ECDSAP256SHA256")
if zsk.protocol != 3:
    # The protocol value must be set to 3.
    # Reference: https://www.rfc-editor.org/rfc/rfc4034#section-2.1.2
    raise Exception("Invalid DNSKEY: protocol not set to 3")

rrsig = fetch_rrsig()
# https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
if rrsig.algorithm != 13:
    raise Exception("expected RRSIG algorithm 13: ECDSAP256SHA256")

# From https://www.rfc-editor.org/rfc/rfc6605.html#section-4:
#   ECDSA public keys consist of a single value, called "Q" in FIPS
#   186-3.  In DNSSEC keys, Q is a simple bit string that represents the
#   uncompressed form of a curve point, "x | y".
#
# The key is already base64 decoded by the dnslib library, which is required following
# https://www.rfc-editor.org/rfc/rfc4034#section-2.2.
zsk_point = ecdsa.ellipticcurve.Point.from_bytes(curve=ecdsa.NIST256p.curve, data=zsk.key)
verifier = ecdsa.VerifyingKey.from_public_point(point=zsk_point, curve=ecdsa.NIST256p)

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

# How to build up the data being verified, continued with resource records.
#   signature = sign(RRSIG_RDATA | RR(1) | RR(2)... )where "|" denotes concatenation;
#
#   RR(i) = owner | type | class | TTL | RDATA length | RDATA
#
# See https://www.rfc-editor.org/rfc/rfc1035#section-3.2.1 for the wire format
# description.
rrs = fetch_a_records()
if len(rrs) != 1:
    raise Exception("Example expects a single A record to verify")
rr_data = bytearray()
rr_data.extend(encode_name(str(rrs[0].rname)))
rr_data.extend(rrs[0].rtype.to_bytes(length=2, byteorder='big'))
rr_data.extend(rrs[0].rclass.to_bytes(length=2, byteorder='big'))
rr_data.extend(rrs[0].ttl.to_bytes(length=4, byteorder='big'))
# rdlength doesn't seem to work
rr_data.extend(int(4).to_bytes(length=2, byteorder='big'))
for b in rrs[0].rdata.data:
    rr_data.extend(b.to_bytes(length=1, byteorder='big'))

data.extend(rr_data)

# From https://www.rfc-editor.org/rfc/rfc6605.html#section-4:
#   The two integers, each of which is formatted as a simple octet string, are combined 
#   into a single longer octet string for DNSSEC as the concatenation "r | s".
#
# So let's use the "raw" signature decoder.
verifier.verify(signature=rrsig.sig, data=data, hashfunc=hashlib.sha256, sigdecode=ecdsa.util.sigdecode_string)
