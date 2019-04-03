#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time

from switchyard.lib.packet.util import *
from switchyard.lib.userlib import *

class Router(object):
    def __init__(self, net):
        self.net = net
        self.pkt_queue = []
        # Ip addresses are keys and
        self.arp_tbl = {}
        self.interfaces = net.interfaces()
        # other initialization stuff here


    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        while True:
            gotpkt = True
            try:
                timestamp,input_port,pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            # simply add the packet to the queue to be processed
            if gotpkt:
                self.pkt_queue.append(pkt)
                log_debug("Got a packet: {}".format(str(pkt)))

            if len(self.pkt_queue) > 0:
                pkt = self.pkt_queue.pop(0)
                if pkt.get_header(Arp):
                    self.handle_arp(pkt.get_header(Arp), input_port)

    def handle_arp(self, arp, input_port):
        if arp.operation == ArpOperation.Request:
            # check if the dest IP is in our interfaces
            for intf in self.interfaces:
                if intf.ipaddr == arp.targetprotoaddr:
                    # TODO: are senders and targets backwards?
                    reply = create_ip_arp_reply(srchw=intf.ethaddr,
                                                srcip=arp.targetprotoaddr,
                                                dsthw=arp.senderhwaddr,
                                                targetip=arp.senderprotoaddr)
                    self.net.send_packet(input_port, reply)
            return #drop packet if we dont have the IP on this router
        else: #we received a reply
            for intf in self.interfaces:
                if intf.ipaddr == arp.targetprotoaddr:
                    # update arp table on reply where the destination is us
                    self.arp_tbl[arp.targetprotoaddr] = arp.targethwaddr
            return


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
