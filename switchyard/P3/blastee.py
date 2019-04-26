#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from threading import *
import time

def create_raw_packet_header(type, pkt_num):
    return bytes(str(type) + ' ' + str(pkt_num), 'utf8')

def extract_sequence_num(data):
    string_data = str(data)
    try:
        num = int(string_data.split().pop(-1))
    except:
        print('error in blastee extracting the sequence number')
        assert False

    return num

def switchy_main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]

    while True:
        gotpkt = True
        try:
            timestamp,dev,pkt = net.recv_packet()
            log_debug("Device is {}".format(dev))
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("I got a packet from {}".format(dev))
            log_debug("Pkt: {}".format(pkt))
        else:
            continue

        #extract the sequence number from our header
        seq_num = extract_sequence_num(pkt[3])
        # generate the ACK packet with the corresponding number
        eth_header = Ethernet(src=pkt[0].dst,
                              dst=pkt[0].src,
                              ethertype=EtherType.IPv4)

        ack_data = create_raw_packet_header('ACK', seq_num)
        pkt[0] = eth_header
        pkt[3] = ack_data

        net.send_packet(dev.name, pkt)

    net.shutdown()
