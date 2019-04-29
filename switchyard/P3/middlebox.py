#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from switchyard.lib import logging
from threading import *
import random
import time

def drop(percent):
    return random.randrange(100) < percent

def switchy_main(net):
    logging.setup_logging(True)

    print("starting midllebox setup")

    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]

    BLASTEE_ETHADDR = EthAddr('20:00:00:00:00:01')
    BLASTER_ETHADDR = EthAddr('10:00:00:00:00:01')


    # extract interface objects
    blaster_intf = None
    blastee_intf = None
    for intf in my_intf:
        if intf.name == 'middlebox-eth0':
            blaster_intf = intf
            #assert blaster_intf.ethaddr == BLASTER_ETHADDR
        elif intf.name == 'middlebox-eth1':
            blastee_intf = intf
            #assert blastee_intf.ethaddr == BLASTEE_ETHADDR
    if not blaster_intf or not blastee_intf:
        print('error getting middlebox interfaces')
        assert False

    # Parsing the arguments file?
    with open('middlebox_params.txt') as params:
        args = params.readline().split()
    if len(args) < 4:
        print('Arguments issue in middlebox')
        assert False
    percent = int(args[3])
    random_seed = int(args[1])

    random.seed(random_seed) #Extract random seed from params file

    log_debug('Setup middlebox:\n\tDrop rate = {}\n\tRandomSeed = {}'.format(percent, random_seed))
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
            # TODO: doublle check the src and dest
            eth_header = Ethernet(src=blaster_intf.ethaddr,
                                  dst=BLASTEE_ETHADDR,
                                  ethertype=EtherType.IPv4)
            pkt[0] = eth_header
            net.send_packet("middlebox-eth1", pkt)
        elif dev == "middlebox-eth1":
            log_debug("Received from blastee")
            '''
            Received ACK
            Modify headers & send to blaster. Not dropping ACK packets!
            '''
            # TODO: dooublle check the src and dest
            eth_header = Ethernet(src=blastee_intf.ethaddr,
                                  dst=BLASTER_ETHADDR,
                                  ethertype=EtherType.IPv4)
            pkt[0] = eth_header
            net.send_packet("middlebox-eth0", pkt)
        else:
            log_debug("Oops :))")

    net.shutdown()
