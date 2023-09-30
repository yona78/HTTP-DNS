import sys
import ipaddress
i, o, e = sys.stdin, sys.stdout, sys.stderr
from scapy.all import *
sys.stdin, sys.stdout, sys.stderr = i, o, e

IP_LISTEN = '0.0.0.0'
PORT = 8153
SOCKET_TIMEOUT = 0.1
LENGTH_FIELD_SIZE = 1024


def send_data(client_socket, data):
    # the function get socket and send him the data the function received
    http_response = "HTTP/1.1 200 OK\r\nContent-Length:" + str(
        len(data)) + "\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
    client_socket.send(http_response.encode())
    client_socket.send(data.encode())


def is_ip(check):
    # the function check if the received ip address is real
    try:
        _ = ipaddress.ip_address(check)
        return True
    except ValueError:
        return False


def find_url(client_socket, ip_address_to_send):
    # the function find the url of the ip address and send it to the socket
    check = is_ip(ip_address_to_send)
    # check if the ip_address_to_get is an ip address
    if check:
        if ipaddress.ip_address(ip_address_to_send).is_private:
            to_send = "private address"
            send_data(client_socket, to_send)
            return
        # check if ip_address_to_get is a private address or not
        help1 = ip_address_to_send.split('.')
        help1.reverse()
        help2 = '.'.join(help1)
        # the program reverse the address
        send_pkt = IP(dst="8.8.8.8") / UDP() / DNS(rd=1, qd=DNSQR(qname=help2 + ".in-addr.arpa", qtype="PTR"))
        rec_pkt = sr1(send_pkt, timeout=3, verbose=False)
        # get the url from the ip address
        try:
            to_send = str(rec_pkt[DNSRR].rdata)
            to_send = to_send[2:-1]
            send_data(client_socket, to_send)
            return
            # if the dns server know the url the program send to the client the url
        except IndexError:
            to_send = "*** UnKnown can't find " + ip_address_to_send + ": Non-existent domain"
            send_data(client_socket, to_send)
            # if the dns server doesn't know the url the program send to the client that
    else:
        to_send = "there is a problem with the ip"
        send_data(client_socket, to_send)
        # if the program didn't get an ip address it send warning


def find_ip(client_socket, url_to_send):
    # the function find the ip_address of the url and send it to the socket
    check = is_ip(url_to_send)
    # check if the ip_address_to_get is an ip address
    if check:
        to_send = "you sent a ip address,please send url"
        send_data(client_socket, to_send)
        # if the program didn't get a url address it send warning
        return
    else:
        dns_packet = IP(dst='8.8.8.8') / UDP(sport=24601, dport=53) / DNS(qdcount=1, rd=1) / DNSQR(qname=url_to_send)
        rec_pkt = sr1(dns_packet, timeout=3, verbose=False)
        # get the ip address from the url
        to_send = ''
        if rec_pkt[DNS].ancount == 0:
            to_send = "*** UnKnown can't find " + url_to_send + ": Non-existent domain"
            send_data(client_socket, to_send)
            # if the dns server doesn't know the ip the program send to the client that
        for x in range(rec_pkt[DNS].ancount):
            if is_ip(str(rec_pkt[DNSRR][x].rdata)):
                to_send += str(rec_pkt[DNSRR][x].rdata)
                to_send += "</p>"
        send_data(client_socket, to_send)
        # the program add all the ip address it received and send them to the client


def handle_client_request(resource, client_socket):
    # the program find the right respond to the client request
    if len(resource) == 0:
        to_send = "welcome, please enter ip or url"
        send_data(client_socket, to_send)
        # if the client didn't send request the program send him welcome
    elif "reverse/" in resource:
        find_url(client_socket, resource[8:])
        # if the user want reverse lookup the function send him
    else:
        find_ip(client_socket, resource)
        # the normal lookup


def validate_http_request(request):
    """Check if request is a valid HTTP request and returns TRUE / FALSE and the requested URL """
    help2 = (request.split("\r\n"))[0].split()
    if len(help2) == 3:
        if help2[0] == "GET":
            if help2[2] == "HTTP/1.1":
                return True, help2[1]
    return False, "there is a problem"


def handle_client(client_socket):
    # the function get the client request and check if it's ok
    print('Client connected')
    while True:
        client_request = client_socket.recv(LENGTH_FIELD_SIZE).decode()
        valid_http, resource = validate_http_request(client_request)
        # the server received the request from the client and check it
        if valid_http:
            print('Got a valid HTTP request')
            handle_client_request(resource[1:], client_socket)
            break
            # if the http request is ok the function handle it
        else:
            print('Error: Not a valid HTTP request')
            http_response = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 16\r\nContent-Type: " \
                            "text/html\r\n\r\nThere is a problem "
            client_socket.send(http_response.encode())
            break
            # if the request is not ok the server send warning
    print('Closing connection')
    client_socket.close()


def main():
    # the main function that create the server and get connection
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((IP_LISTEN, PORT))
    server_socket.listen()
    print("Listening for connections on port {}".format(PORT))
    while True:
        try:
            client_socket, client_address = server_socket.accept()
            print('New connection received')
            client_socket.settimeout(SOCKET_TIMEOUT)
            handle_client(client_socket)
        except socket.timeout:
            print("nobody connected")


if __name__ == '__main__':
    main()
