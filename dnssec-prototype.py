#!/usr/bin/env python3

import dnslib
import ecdsa
import hashlib
import io
import rsa
import socket

# int to/from bytes conversions all assume network byte order.
def int_to_bytes(i, length):
    return i.to_bytes(length, byteorder='big')

def bytes_to_int(bytes):
    return int.from_bytes(bytes, byteorder='big')


def dnskey_key_tag(dnskey):
    # See https://www.rfc-editor.org/rfc/rfc4034#appendix-B.
    packed_rdata = dnslib.Buffer()
    dnskey.pack(packed_rdata)

    key_tag = 0
    i = 0
    while i < len(packed_rdata.data):
        key_tag += bytes_to_int(packed_rdata.data[i:i+2])
        i += 2
    key_tag += (key_tag >> 16) & 0xFFFF
    return key_tag & 0xFFFF


def send(name_server_address, bytes, protocol):
    client_socket = socket.socket(socket.AF_INET, protocol)
    if protocol == socket.SOCK_STREAM:
        print("connecting")
        client_socket.connect((name_server_address, 53))
        print("sending")
        client_socket.sendall(bytes)
        print("receiving")
        return client_socket.recv(4096)
    elif protocol == socket.SOCK_DGRAM:
        # Binding to port zero allows the os to choose an available port
        client_socket.bind(('', 0))        
        client_socket.sendto(bytes, (name_server_address, 53))
        raw_response, _ = client_socket.recvfrom(4096)
        return raw_response
    else:
        raise Exception("Unsupported protocol:", protocol)


def query_nameserver(question, name_server_address):
    query = dnslib.DNSRecord(q=question)
    # Disabling the recursion desired bit, so that this toy project
    # handles recursion requirements.
    query.header.set_rd(False)

    # Using EDNS0, set the DNSSEC OK bit to return RRSIG records. 
    # See https://www.rfc-editor.org/rfc/rfc3225 for how this works. 
    query.add_ar(dnslib.EDNS0(flags="do", udp_len=4096))

    raw_response = send(name_server_address, query.pack(), socket.SOCK_DGRAM)
    parsed_response = dnslib.DNSRecord.parse(raw_response)
    #print("received name server response:", parsed_response)
    if parsed_response.header.tc:
        # DNSSEC resource records easily pressure beyond UDP payload limits.
        print("retrying over TCP")
        raw_response = send(name_server_address, query.pack(), socket.SOCK_STREAM)
        parsed_response = dnslib.DNSRecord.parse(raw_response)
    return parsed_response


def fetch_records(name_server_address, question):
    response = query_nameserver(question, name_server_address)
    if response.get_a().rtype != question.qtype:
        raise Exception("expected rtype {}, but received {}", question.qtype, response.get_a().rtype)
    rrs = []
    for rr in response.rr:
        if rr.rtype == question.qtype:
            rrs.append(rr)
        elif rr.rtype == dnslib.QTYPE.RRSIG:
            rrsig = rr
    return rrs, rrsig.rdata


def get_zone_signing_keys(dnskeys):
    # There can be multiple zone signing keys. 
    #
    # From https://www.rfc-editor.org/rfc/rfc4035#section-2.1:
    #   For each private key used to create RRSIG RRs in a zone, 
    #   the zone SHOULD include a zone DNSKEY RR containing the 
    #   corresponding public key.
    keys = []
    for rr in dnskeys:
        # The zone signing key has flag field set to 256.
        # Reference: https://www.rfc-editor.org/rfc/rfc4034#section-2.1.1
        if rr.rdata.flags == 256:
            keys.append(rr)
    return keys


def get_key_signing_keys(dnskeys):
    # Similar to zone signing keys, there can be multiple key signing keys.
    keys = []
    for rr in dnskeys:
        # The key signing key has flag field set to 257.
        # Reference: https://www.rfc-editor.org/rfc/rfc4034#section-2.1.1
        if rr.rdata.flags == 257:
            keys.append(rr)
    return keys


def canonical_order(rrs):
    # See https://www.rfc-editor.org/rfc/rfc4034#section-6 for how to 
    # order canonically. 
    #
    # This naive implementation just does bytewise ordering in an RR's rdata.
    packed_rrs = []
    for rr in rrs:
        rdata = dnslib.Buffer()
        rr.rdata.pack(rdata)
        packed_rrs.append(rdata.data)
    sorted_indices = [i[0] for i in sorted(enumerate(packed_rrs), key=lambda x:x[1])]

    result = []
    for i in sorted_indices:
        result.append(rrs[i])
    return result



def encode_name(name):
    # From https://www.rfc-editor.org/rfc/rfc1035#section-3.1:
    #   Domain names in messages are expressed in terms of a sequence of labels.
    #   Each label is represented as a one octet length field followed by that
    #   number of octets.  Since every domain name ends with the null label of
    #   the root, a domain name is terminated by a length byte of zero.    
    if name == '.':
        return bytearray(b'\x00')
    
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
    data.extend(int_to_bytes(rrsig.covered, length=2))
    # One byte for algorithm
    data.extend(int_to_bytes(rrsig.algorithm, length=1))
    # One byte for labels
    data.extend(int_to_bytes(rrsig.labels, length=1))
    # Four bytes for original ttl
    data.extend(int_to_bytes(rrsig.orig_ttl, length=4))
    # Four bytes for signature expiration
    data.extend(int_to_bytes(rrsig.sig_exp, length=4))
    # Four bytes for signature inception
    data.extend(int_to_bytes(rrsig.sig_inc, length=4))
    # Two bytes for the key tags.
    data.extend(int_to_bytes(rrsig.key_tag, length=2))
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
        data.extend(int_to_bytes(rr.rtype, length=2))
        data.extend(int_to_bytes(rr.rclass, length=2))
        data.extend(int_to_bytes(rr.ttl, length=4))

        if rr.rtype == dnslib.QTYPE.A:
            # TODO: this assumes A record type
            # rdlength doesn't seem to work
            data.extend(int_to_bytes(4, length=2))
            for b in rr.rdata.data:
                data.extend(int_to_bytes(b, length=1))
        elif rr.rtype in [dnslib.QTYPE.DNSKEY, dnslib.QTYPE.DS]:
            rdata = dnslib.Buffer()
            rr.rdata.pack(rdata)
            # Appending rdlength
            data.extend(int_to_bytes(len(rdata.data), length=2))
            # Appending rdata
            data.extend(rdata.data)            
        else:
            raise Exception("Unexpected RR type to sign:", rr.rtype)

    return data


def verify_with_ecdsa_sha256(signing_key, rrsig, bytes_to_verify):
    # Algorithm 13 is described at https://www.rfc-editor.org/rfc/rfc6605.
    if signing_key.algorithm != 13:
        raise Exception("expected signing algorithm 13: ECDSAP256SHA256")
    if rrsig.algorithm != 13:
        raise Exception("expected RRSIG algorithm 13: ECDSAP256SHA256")
    
    # From https://www.rfc-editor.org/rfc/rfc6605.html#section-4:
    #   ECDSA public keys consist of a single value, called "Q" in FIPS
    #   186-3.  In DNSSEC keys, Q is a simple bit string that represents the
    #   uncompressed form of a curve point, "x | y".
    #
    # The key is already base64 decoded by the dnslib library, which is required following
    # https://www.rfc-editor.org/rfc/rfc4034#section-2.2.
    point = ecdsa.ellipticcurve.Point.from_bytes(curve=ecdsa.NIST256p.curve, data=signing_key.key)
    verifier = ecdsa.VerifyingKey.from_public_point(point=point, curve=ecdsa.NIST256p)

    # From https://www.rfc-editor.org/rfc/rfc6605.html#section-4:
    #   The two integers, each of which is formatted as a simple octet string, are combined 
    #   into a single longer octet string for DNSSEC as the concatenation "r | s".
    #
    # So let's use the "raw" signature decoder.
    verifier.verify(signature=rrsig.sig, data=bytes_to_verify, hashfunc=hashlib.sha256, sigdecode=ecdsa.util.sigdecode_string)


def verify_with_rsa_sha256(signing_key, rrsig, bytes_to_verify):
    # Algorithm 8 is described at https://www.rfc-editor.org/rfc/rfc5702.html. 
    #
    # Essential documentation also be the original RSA algorithm: https://www.rfc-editor.org/rfc/rfc3110.
    if signing_key.algorithm != 8:
        raise Exception("expected signing algorithm 8: RSASHA256")
    if rrsig.algorithm != 8:
        raise Exception("expected RRSIG algorithm 8: RSASHA256")
    
    # From https://www.rfc-editor.org/rfc/rfc3110#section-2:
    #  RSA public keys are stored in the DNS as KEY RRs using algorithm
    #  number 5 [RFC2535].  The structure of the algorithm specific portion
    #  of the RDATA part of such RRs is as shown below.
    #
    #     Field             Size
    #     -----             ----
    #     exponent length   1 or 3 octets (see text)
    #     exponent          as specified by length field
    #     modulus           remaining space

    # See https://en.wikipedia.org/wiki/65,537 for a commonly exponent used in RSA public keys.
    exponent_length = signing_key.key[0]
    if exponent_length == 0:
        raise Exception("3 octet exponent length parsing is not implemented")
    public_key = rsa.PublicKey(n = bytes_to_int(signing_key.key[1+exponent_length:]), 
                               e = bytes_to_int(signing_key.key[1:1+exponent_length]))
    rsa.verify(message=io.BytesIO(bytes_to_verify), signature=rrsig.sig, pub_key=public_key)


def verify_data(signing_keys, rrsig, rrs):
    # From https://www.rfc-editor.org/rfc/rfc4034#section-3.1.6:
    #    The Key Tag field contains the key tag value of the DNSKEY RR that
    #    validates this signature, in network byte order.    
    validating_signing_key = None
    for signing_key in signing_keys:
        if signing_key.rdata.protocol != 3:
            # The protocol value must be set to 3.
            # Reference: https://www.rfc-editor.org/rfc/rfc4034#section-2.1.2
            raise Exception("Invalid DNSKEY: protocol not set to 3")
        if dnskey_key_tag(signing_key.rdata) == rrsig.key_tag:
            validating_signing_key = signing_key.rdata
            break
    if not validating_signing_key:
        raise Exception("Failed to find validating signing key for RRSIG={}", rrsig.key_tag)

    data = bytearray()
    data.extend(build_rrsig_signing_data(rrsig))
    data.extend(build_rrs_signing_data(canonical_order(rrs)))

    # https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml.
    if validating_signing_key.algorithm == 13:
        verify_with_ecdsa_sha256(validating_signing_key, rrsig, data)
    elif validating_signing_key.algorithm == 8:
        verify_with_rsa_sha256(validating_signing_key, rrsig, data)
    else:
        raise Exception("Unexpected verifying algorithm:", validating_signing_key.algorithm)    
    print("RRSIG={} and DNSKEY={} verifies the {} resource records".format(
        rrsig.key_tag, 
        dnskey_key_tag(validating_signing_key), 
        dnslib.QTYPE[rrs[0].rtype]))


def verify_ksk_against_ds(ds, key_signing_keys):
    # From https://www.rfc-editor.org/rfc/rfc4034#section-5.1.1:
    #   The Key Tag field lists the key tag of the DNSKEY RR referred to by
    #   the DS record...
    ksk_to_authenticate = None
    for ksk in key_signing_keys:
        if dnskey_key_tag(ksk.rdata) == ds.key_tag:
            ksk_to_authenticate = ksk
            break
    if not ksk_to_authenticate:
        raise Exception("Failed to find DNSKEY to authenticate for DS={}", ds.key_tag)

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
    data.extend(encode_name(str(ksk_to_authenticate.rname)))
    
    dnskey_rdata = dnslib.Buffer()
    ksk_to_authenticate.rdata.pack(dnskey_rdata)
    data.extend(dnskey_rdata.data)

    if hashlib.sha256(data).hexdigest() != ds.digest.hex():
        raise Exception("Failed to validate against the parent DS record. SHA256 mismatch!")
    print("DS={} verifies DNSKEY={}".format(ds.key_tag, dnskey_key_tag(ksk_to_authenticate.rdata)))

#############################################
### Running verification, from bottom-to-top.
############################################# 

###########################################################
# Step 1: verifying authoritive A records about example.com

# Fetching DNSKEYS from a.iana-servers.net.
dnskeys, dnskey_rrsig = fetch_records("199.43.135.53", dnslib.DNSQuestion("example.com.", dnslib.QTYPE.DNSKEY))

# Verifying zone data
# Fetching A records from a.iana-servers.net.
rrs, a_rrsig = fetch_records("199.43.135.53", dnslib.DNSQuestion("example.com.", dnslib.QTYPE.A))
verify_data(get_zone_signing_keys(dnskeys), a_rrsig, rrs)

# Verifying key data
verify_data(get_key_signing_keys(dnskeys), dnskey_rrsig, dnskeys)

################################################################
# Step 2: verifying information from the parent top level domain

# Fetch the parent's DS record about "example.com", from a.gtld-servers.net.
tld_ds, tld_ds_rrsig = fetch_records("192.5.6.30", dnslib.DNSQuestion("example.com.", dnslib.QTYPE.DS))
verify_ksk_against_ds(tld_ds[0].rdata, get_key_signing_keys(dnskeys))

# Verify the parent's DS records against the zone signing key.
tld_dnskeys, tld_dnskey_rrsig = fetch_records("192.5.6.30", dnslib.DNSQuestion("com.", dnslib.QTYPE.DNSKEY))
verify_data(get_zone_signing_keys(tld_dnskeys), tld_ds_rrsig, tld_ds)

# Verifying DNSKEYS in the parent com. top level domain
verify_data(get_key_signing_keys(tld_dnskeys), tld_dnskey_rrsig, tld_dnskeys)

####################################################################
# Step 3: verifying information about the top level domain from root

# Fetch the root DS record about "com", from a.root-servers.net.
root_ds, root_ds_rrsig = fetch_records("198.41.0.4", dnslib.DNSQuestion("com.", dnslib.QTYPE.DS))
verify_ksk_against_ds(root_ds[0].rdata, get_key_signing_keys(tld_dnskeys))

# Verify the root's DS records against the zone signing key.
root_dnskeys, root_dnskey_rrsig = fetch_records("198.41.0.4", dnslib.DNSQuestion(".", dnslib.QTYPE.DNSKEY))
verify_data(get_zone_signing_keys(root_dnskeys), root_ds_rrsig, root_ds)

# Verify the DNSKEYS in root.
verify_data(get_key_signing_keys(root_dnskeys), root_dnskey_rrsig, root_dnskeys)

######################################################################
# Step 4: verifying root key signing key against the trust anchor's DS

# Hardcoding the latest DS record from  http://data.iana.org/root-anchors/root-anchors.xml.
trust_anchor = dnslib.DS(key_tag=20326, 
                         algorithm=8, 
                         digest_type=2, 
                         digest=bytes.fromhex("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"))
verify_ksk_against_ds(trust_anchor, get_key_signing_keys(root_dnskeys))