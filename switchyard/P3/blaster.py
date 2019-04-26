#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from random import randint
import time

def print_output(total_time, num_ret, num_tos, throughput, goodput):
    print("Total TX time (s): " + str(total_time))
    print("Number of reTX: " + str(num_ret))
    print("Number of coarse TOs: " + str(num_tos))
    print("Throughput (Bps): " + str(throughput))
    print("Goodput (Bps): " + str(goodput))

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
    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]

    # Parsing the arguments file
    with open('blaster_params.txt') as params:
        args = params.readline().split()
    if len(args) < 10:
        print('Arguments issue in blaster')
        assert False
    NUM_PKTS = int(args[1])
    LENGTH = int(args[3])
    SENDER_WINDOW = int(args[5])
    TIMEOUT = int(args[7])
    RECV_TIMEOUT = int(args[9])

    while True:
        gotpkt = True
        try:
            #Timeout value will be parameterized!
            timestamp,dev,pkt = net.recv_packet(timeout=0.15)
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("I got a packet")
        else:
            log_debug("Didn't receive anything")

            '''
            Creating the headers for the packet
            '''
            pkt = Ethernet() + IPv4() + UDP()
            pkt[1].protocol = IPProtocol.UDP

            '''
            Do other things here and send packet
            '''

    net.shutdown()
