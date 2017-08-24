# Packet sniffer in python
# For Linux - Sniffs all incoming and outgoing packets :)

import socket, sys
from struct import *
import threading
import socketserver
import time

from cassandra.cluster import Cluster
from cassandra.query import SimpleStatement

from util import (
    parent_path,
    ParsingError,
    read_bool,
    read_buffer,
    read_int_bool_int,
    read_int_long_int_long,
    read_long,
    read_number,
    read_string,
    StringTooLong,
)

# Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
    return b


# used to construct a reply to zookeeper read requests
def make_udp_header(src_port, dst_port, data_len):
    return pack("!4H", src_port, dst_port, data_len + 8, 0)


def make_ip_header():
    src_ip = "\x0a\x00\x00\x03"
    dst_ip = "\x0a\x00\x00\x02"
    ip_header = "\x45\x00\x00\x54\x05\x9f\x40\x00\x40\x11\x2f\x93" + src_ip + dst_ip
    return ip_header


# create a AF_PACKET type raw socket (thats basically packet level)
# define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
# define ETH_P_IP     0x0800
def connect():
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
        s_send = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        s_send.bind(("eth0", 0))
        return s, s_send
    except socket.error:
        print('Socket could not be created: %s' % (socket.error))
        sys.exit()


class Record(threading.Thread):
    def __init__(self, shared_log, shared_lock):
        threading.Thread.__init__(self)
        self.MAX_REQUEST_SIZE = 100 * 1024 * 1024
        self.log = shared_log
        self.s, self.s_send = connect()
        self.watermark_low = 0
        self.watermark_high = 0
        self.corfu_lock = shared_lock

    def run(self):
        while True:
            packet_raw = self.s.recvfrom(65565)

            # packet string from tuple
            packet = packet_raw[0]

            # parse ethernet header
            eth_length = 14
            eth_header = packet[:eth_length]
            eth = unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth[2])
            # print('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))

            # Parse IP packets, IP Protocol number = 8
            if eth_protocol == 8:
                # Parse IP header
                # take first 20 characters for the ip header
                ip_header = packet[eth_length:20 + eth_length]
                # now unpack them :)
                iph = unpack('!BBHHHBBH4s4s', ip_header)
                version_ihl = iph[0]
                version = version_ihl >> 4
                ihl = version_ihl & 0xF
                iph_length = ihl * 4
                ttl = iph[5]
                protocol = iph[6]
                s_addr = socket.inet_ntoa(iph[8])
                d_addr = socket.inet_ntoa(iph[9])
                # print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' +
                #       str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))

                # TCP protocol
                if protocol == 6:
                    t = iph_length + eth_length
                    tcp_header = packet[t:t + 20]
                    # now unpack them :)
                    tcph = unpack('!HHLLBBHHH', tcp_header)
                    source_port = tcph[0]
                    dest_port = tcph[1]
                    sequence = tcph[2]
                    acknowledgement = tcph[3]
                    doff_reserved = tcph[4]
                    tcph_length = doff_reserved >> 4

                    # print('Source Port: ' + str(source_port) + ' Dest Port: ' + str(dest_port) + ' Sequence Number: ' +
                    #       str(sequence) + ' Acknowledgement: ' + str(acknowledgement) + ' TCP header length: ' +
                    #       str(tcph_length))

                    # parse zookeeper protocol
                    if dest_port == 9042:
                        # first parse corfu-wrapper
                        # corfu_t = eth_length + iph_length + tcph_length * 4
                        # packet_to_send = eth_header + ip_header + packet[t:t + tcph_length * 4] + packet[corfu_t + 4:]

                        # corfu_header = packet[corfu_t:corfu_t + 4]
                        # corfuh = unpack('!i', corfu_header)
                        # wid = corfuh[0]
                        # print("write request id: %s" % wid)
                        # next parse original zoo-keeper protocol
                        # h_size = eth_length + iph_length + tcph_length * 4 + 4
                        h_size = eth_length + iph_length + tcph_length * 4
                        data_size = len(packet) - h_size
                        if data_size == 0:
                            self.s_send.send(packet)
                            continue
                        # get data from the packet
                        data = packet[h_size:]
                        # print('Data: ' + data)
                        # now analyze zookeeper
                        sid, offset = read_number(data, 0)
                        header_skip, offset = read_number(data, offset)
                        opcode, offset = read_bool(data, offset)
                        # print("sid: %s, opcode: %s" % (sid, opcode))
                        self.corfu_lock.acquire()
                        if len(self.log) <= sid:
                            self.log.extend([None for _ in range(len(self.log))])
                        if self.log[sid] is None:
                            self.log[sid] = packet[h_size:]
                        self.s_send.send(packet)
                        self.corfu_lock.release()

                # ICMP Packets
                elif protocol == 1:
                    u = iph_length + eth_length
                    icmph_length = 4
                    icmp_header = packet[u:u + 4]

                    # now unpack them :)
                    icmph = unpack('!BBH', icmp_header)

                    icmp_type = icmph[0]
                    code = icmph[1]
                    checksum = icmph[2]

                    print('Type : %s Code : %s Checksum : %s' % (str(icmp_type), str(code), str(checksum)))

                    h_size = eth_length + iph_length + icmph_length
                    data_size = len(packet) - h_size

                    # get data from the packet
                    data = packet[h_size:]
                # UDP packets
                elif protocol == 17:
                    u = iph_length + eth_length
                    udph_length = 8
                    udp_header = packet[u:u + 8]

                    # now unpack them :)
                    udph = unpack('!HHHH', udp_header)

                    source_port = udph[0]
                    dest_port = udph[1]
                    length = udph[2]
                    checksum = udph[3]

                    print('Source Port : %s Dest Port : %s Length : %s Checksum : %s' % (str(source_port), str(dest_port),
                                                                                     str(length), str(checksum)))

                    h_size = eth_length + iph_length + udph_length
                    data_size = len(packet) - h_size

                    # get data from the packet
                    data = packet[h_size:]
                    print('Data : %s' % data)

                # some other IP packet like IGMP
                else:
                    print('Protocol other than TCP/UDP/ICMP')


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


class QueryHandler(socketserver.BaseRequestHandler):
    def handle(self):
        # Echo the back to the client
        while True:
            data = self.request.recv(1024)
            if not data:
                print('client closing')
                return
            query_header = unpack('!iii', data[0:12])
            query_type = query_header[0]
            query_slot_start = query_header[1]
            # query_slot_end points to the index of the next slot of the last missing log
            query_slot_end = query_header[2]
            # print("%s ~ %s slots are queried. " % (query_slot_start, query_slot_end - 1))
            if query_type == 1:
                # block until the queried slot is not None
                for query_slot in range(query_slot_start, query_slot_end):
                    exist_flag = False
                    while exist_flag is False:
                        self.server.corfu_lock.acquire()
                        if self.server.log[query_slot] is not None:
                            self.request.send(self.server.log[query_slot])
                            # print("response for %s is sent." % query_slot)
                            exist_flag = True
                        self.server.corfu_lock.release()
                        # give the record thread 1-second chance to fill the missing slot before retry
                        if exist_flag is False:
                            time.sleep(1)

class QueryServer(threading.Thread):
    def __init__(self, shared_log, shared_lock):
        threading.Thread.__init__(self)
        self.server = None
        self.log = shared_log
        self.corfu_lock = shared_lock


    def run(self):
        if self.server == None:
            self.server = ThreadedTCPServer(('', 2191), QueryHandler)
            self.server.log = self.log
            self.server.corfu_lock = self.corfu_lock
            self.server.serve_forever()


if __name__=="__main__":
    KEYSPACE = "key_space1"
    LOG_INI_SIZE = 200
    corfu_log = [None for _ in range(LOG_INI_SIZE)]
    log_lock = threading.Lock()

    record_server = Record(corfu_log, log_lock)
    query_server = QueryServer(corfu_log, log_lock)

    record_server.start()
    query_server.start()

