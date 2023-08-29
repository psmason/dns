#!/usr/bin/env python3

"""
    Basic examples:
      `dig +tries=1 +timeout=60 @localhost -p 4053 drive.google.com google.com example.com`    

    CNAME example:
      `dig +tries=1 +timeout=60 @localhost -p 4053 www.apple.com`
"""

import dnslib
import enum
import socket
import random
import time
import typing

# https://en.wikipedia.org/wiki/Root_name_server
ROOT_SERVERS = {
    'A': '198.41.0.4',
    'B': '170.247.170.2',
    # There are more roots...    
}

LISTENING_PORT = 4053


def get_random_root_server():
    _, address = random.choice(list(ROOT_SERVERS.items()))
    return address


# Plain-old-data type for respones from name servers.
class NameServerResponseType(enum.Enum):
    # An authoritative server returned NXDOMAIN.
    NXDOMAIN = 0

    # IPv4 IP address
    ANSWER = 1

    # The response provided both a delegate authority server, and its 
    # IPv4 address
    DELEGATE_IP_ADDRESS = 2

    # The response provided only the name of a delegated authority server.
    # IPv4 addresses need to be queries as followup work.
    DELEGATE_NAME = 3

    # A CNAME answer that requires chasing.
    CNAME = 4


def structure_response(parsed_response):
    if parsed_response.header.rcode == dnslib.RCODE.NXDOMAIN:
        return "", NameServerResponseType.NXDOMAIN

    if len(parsed_response.rr):
        # An answer is available
        answer = parsed_response.get_a()
        if answer.rtype == dnslib.QTYPE.A:
            return str(answer.rdata), NameServerResponseType.ANSWER
        elif answer.rtype == dnslib.QTYPE.CNAME:
            return str(answer.rdata), NameServerResponseType.CNAME
    
    # If there no answer, pick from the authority section for the recursive, followup query.
    auth = random.choice(parsed_response.auth)

    # Is the nameserver's IP address provided in the additional section?
    delegate_ip_address = None
    for ar in parsed_response.ar:
        if ar.rtype == dnslib.QTYPE.A and ar.rname == str(auth.rdata):
            delegate_ip_address = str(ar.rdata)
    if delegate_ip_address is not None:
        return delegate_ip_address, NameServerResponseType.DELEGATE_IP_ADDRESS
    
    print("Hit a dead end. Scheduling a new root query:", str(auth.rdata))
    return str(auth.rdata), NameServerResponseType.DELEGATE_NAME


def query_name_server(qname, name_server_ip_address):
    query = dnslib.DNSRecord(q=dnslib.DNSQuestion(qname, dnslib.QTYPE.A))
    # Disabling the recursion desired bit, so that this toy project
    # handles recursion requirements.
    query.header.set_rd(False)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Binding to port zero allows the os to choose an available port
    client_socket.bind(('', 0))        
    
    # In case of bugs, let's make sure we query nameservers slowly.
    time.sleep(0.5)

    print("querying name server for qname:", qname, (name_server_ip_address, 53))
    client_socket.sendto(query.pack(), (name_server_ip_address, 53))

    raw_response, _ = client_socket.recvfrom(1024)
    parsed_response = dnslib.DNSRecord.parse(raw_response)
    print("received name server response:", parsed_response)

    return structure_response(parsed_response)


def resolve_name(question):
    # Resolution starts at a (randomly selected) root server.
    current_name_server_address = get_random_root_server()

    # A stack tracking still-required work. If recursing hits a dead-end, and 
    # additional queries are needed starting at the root, we append to the 
    # stack. 
    #
    # Once the stack is empty, we have a deliverable answer.
    query_name_stack = [str(question.get_qname())]

    response = dnslib.DNSRecord(
            # Bits set in the response:
            # qr:1 - indicates a response
            # aa:0 - indicates a non-authoritative response
            # ra:1 - indicates the server supports recursion (this toy server is a recursive resolver)
            dnslib.DNSHeader(qr=1,aa=0,ra=1), 
            q=question)
    while True:
        name_server_response, name_server_response_type = query_name_server(query_name_stack[-1], current_name_server_address)
        
        if name_server_response_type == NameServerResponseType.ANSWER:
            # We've answered whatever work item is at the top of the stack.
            query_name_stack.pop()
            if len(query_name_stack) == 0:
                # We're done. 
                response.rr.append(dnslib.RR(str(question.get_qname()), rdata=dnslib.A(name_server_response)))
                return response
            else:
                # Keep working, using the answer as the next name server address
                current_name_server_address = name_server_response
        elif name_server_response_type == NameServerResponseType.DELEGATE_NAME:
            # We're still trying to answer some targeted resource name, so it stays 
            # in the work stack. But there's an additional name server to resolve, 
            # which needs to be resolved from the root.
            query_name_stack.append(name_server_response)
            # Updating ns address to restart resolution from a root server
            current_name_server_address = get_random_root_server()
        elif name_server_response_type == NameServerResponseType.CNAME:
            # CNAME records need to be reported to the client.
            response.rr.append(dnslib.RR(query_name_stack[-1], rtype=dnslib.QTYPE.CNAME, rdata=dnslib.CNAME(name_server_response)))
            # The CNAME result means there's no further work to do for the current resource name.
            query_name_stack.pop()
            # But we chase down the CNAME, starting from the root. 
            query_name_stack.append(name_server_response)
            current_name_server_address = get_random_root_server()
        elif name_server_response_type == NameServerResponseType.DELEGATE_IP_ADDRESS:
            # Keep traversing with the updating name server address
            current_name_server_address = name_server_response
        elif name_server_response_type == NameServerResponseType.NXDOMAIN:
            # NXDOMAIN interrupts all work. 
            response.header.set_rcode(dnslib.RCODE.NXDOMAIN)
            return response
        else:
            raise Exception("Unexpected response type:", name_server_response_type)


def deliver_response(socket, response_bytes, address):
    print("deliverying reply...")
    socket.sendto(response_bytes, address)


server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(('', LISTENING_PORT))

print("starting server...")
while True:
    message, address = server_socket.recvfrom(1024)

    parsed_message = dnslib.DNSRecord.parse(message)
    print("received DNS request:", parsed_message)

    for question in parsed_message.questions:
        response = resolve_name(question)
        response.header.id = parsed_message.header.id
        deliver_response(server_socket, response.pack(), address)
