#!/usr/bin/env python3

import dnslib
import socket
import random
import time

# https://en.wikipedia.org/wiki/Root_name_server
ROOT_SERVERS = {
    'A': '198.41.0.4',
    'B': '170.247.170.2',
    # There are more roots...    
}

def get_random_root_server():
    _, address = random.choice(list(ROOT_SERVERS.items()))
    return address


def get_address_from_response(parsed_response):
    if len(parsed_response.rr):
        # An answer is available
        return str(parsed_response.get_a().rdata), None, None
    
    # If there no answer, pick from the authority section for the recursive, followup query.
    auth = random.choice(parsed_response.auth)

    # Is the nameserver's IP address provided in the additional section?
    auth_ip_address = None
    for ar in parsed_response.ar:
        if ar.rtype == dnslib.QTYPE.A and ar.rname == str(auth.rdata):
            auth_ip_address = str(ar.rdata)
    if auth_ip_address is not None:
        return None, auth_ip_address, None
    
    print("Hit a dead end. Scheduling a new root query:", str(auth.rdata))
    return None, None, str(auth.rdata)        


def query_name_server(qname, name_server_ip_address):
    query = dnslib.DNSRecord(q=dnslib.DNSQuestion(qname, dnslib.QTYPE.A))
    # Disabling the recusion desired bit, so that this toy project
    # handles recursion requirements.
    query.header.set_rd(False)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Binding to port zero allows the os to choose an available port
    client_socket.bind(('', 0))        
    
    # In case of bugs, let's make sure we query nameservers slowly.
    time.sleep(1.0)

    print("querying name server for qname:", qname, (name_server_ip_address, 53))
    client_socket.sendto(query.pack(), (name_server_ip_address, 53))

    raw_response, _ = client_socket.recvfrom(1024)
    parsed_response = dnslib.DNSRecord.parse(raw_response)
    print("received name server response:", parsed_response)

    return get_address_from_response(parsed_response)


def resolve_name(name):
    # Resolution starts at a (randomly selected) root server.
    name_server_address = get_random_root_server()

    # A stack tracking still-required work. If recursing hits a dead-end, and 
    # additional queries are needed starting at the root, we append to the 
    # stack. 
    #
    # Once the stack is empty, we have a deliverable answer.
    query_name_stack = [name]

    answer = None
    while len(query_name_stack) > 0:
        answer, name_server_address, new_root_query = query_name_server(query_name_stack[-1], name_server_address)
        
        if new_root_query is not None:
            query_name_stack.append(new_root_query)
            # Updating ns address to restart resolution from a root server
            name_server_address = get_random_root_server()
        elif answer is not None:
            query_name_stack.pop()
            # With top-most answer available, potentially use it as the next name server address
            name_server_address = answer
    
    return answer


def deliver_response(socket, response_bytes, address):
    print("deliverying reply...")
    socket.sendto(response_bytes, address)


server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(('', 4053))

print("starting server...")
while True:
    message, address = server_socket.recvfrom(1024)

    parsed_message = dnslib.DNSRecord.parse(message)
    print("received DNS request:", parsed_message)

    for question in parsed_message.questions:
        answer = resolve_name(str(question.get_qname()))
        response = dnslib.DNSRecord(
            # The header indicates a non-authoritative response.
            # Bits set in the response:
            # qr:1 - indicates a response
            # aa:1 - indicates a non-authoritative response
            # ra:1 - indicates the server supports recursion (which is we arrived at an answer)
            dnslib.DNSHeader(id=parsed_message.header.id, qr=1,aa=0,ra=1),
                        q=question,
                        a=dnslib.RR(str(question.get_qname()),rdata=dnslib.A(answer)))
        deliver_response(server_socket, response.pack(), address)
