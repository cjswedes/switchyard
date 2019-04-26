#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from threading import *
import random
import time

def drop(percent):
    return random.randrange(100) < percent

def switchy_main(net):

    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]

    # extract interface objects
    blaster_intf = None
    blastee_intf = None
    for intf in my_intf:
        if intf.name == 'eth0':
            blaster_intf = intf
        elif intf.name == 'eth1':
            blastee_intf = intf
    if not blaster_intf or not blastee_intf:
        print('error getting middlebox interfaces')
        assert False

    # Parsing the arguments file?
    with open('middlebox_params.txt') as params:
        args = params.readline().split()
    if len(args) < 4:
        print('Arguments issue')
        assert False
    percent = int(args[3])
    random_seed = int(args[1])

    random.seed(random_seed) #Extract random seed from params file

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
            log_debug("I got a packet {}".format(pkt))

        if dev == "middlebox-eth0":
            log_debug("Received from blaster")
            '''
            Received data packet
            Should I drop it?

            If not, modify headers & send to blastee
            '''
            if drop(percent=percent):
                continue

            # Create new Ethernet Header for the packet
            # TODO: dooublle check the src and dest
            eth_header = Ethernet(src=blaster_intf.ethaddr,
                                  dst=blastee_intf.ethaddr,
                                  ethertype=EtherType.IPv4)
            pkt[0] = eth_header
            net.send_packet("middlebox-eth1", pkt)
        elif dev == "middlebox-eth1":
            log_debug("Received from blastee")
            '''
            Received ACK
            Modify headers & send to blaster. Not dropping ACK packets!
            '''
            eth_header = Ethernet(src=blastee_intf.ethaddr,
                                  dst=blaster_intf.ethaddr,
                                  ethertype=EtherType.IPv4)
            pkt[0] = eth_header
            net.send_packet("middlebox-eth0", pkt)
        else:
            log_debug("Oops :))")

    net.shutdown()
