#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from switchyard.lib import logging
from threading import *
import time


def create_raw_packet_header(type, pkt_num, length):
    if type == 'SYN':
        type_bytes = b'ffff'
    else:
        type_bytes = b'0000'
    num_bytes = pkt_num.to_bytes(2, byteorder='big')
    res = type_bytes + num_bytes + (b'a' * length)
    log_debug('created SYN header: {}'.format(res))
    return res

def extract_sequence_num(raw_header):
    try:
        header = raw_header.data
        num = int.from_bytes(header[5:6], byteorder='big')
    except:
        print('error in blastee extracting the sequence number')
        assert False

    return num

def switchy_main(net):
    logging.setup_logging(True)

    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]

    BLASTEE_ETHADDR = EthAddr('20:00:00:00:00:01')
    BLASTER_ETHADDR = EthAddr('10:00:00:00:00:01')
    MIDDLEBOX_ETHADDR = EthAddr('40:00:00:00:00:02')

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
        log_debug('extracted seq_num: {}'.format(seq_num))
        # generate the ACK packet with the corresponding number
        ack_data = create_raw_packet_header('ACK', seq_num, 0)
        pkt = Ethernet(src=BLASTEE_ETHADDR,
                       dst=BLASTER_ETHADDR,
                       ethertype=EtherType.IPv4) + \
              IPv4() + \
              UDP()
        pkt[1].protocol = IPProtocol.UDP
        pkt = pkt + ack_data
        log_debug("Sending ACK pkt: {}".format(pkt))
        net.send_packet(dev, pkt)

    net.shutdown()
