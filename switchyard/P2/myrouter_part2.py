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
        self.fwd_tbl = ForwardTable(net)
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
                if pkt.get_header(IPv4):
                    self.handle_IPv4(pkt.get_header(IPv4), input_port)

    def handle_IPv4(self, ip_pkt, input_port):
        # be careful about what to do if you need to send and arp query
        # you should check out the FAQs questions 1, 3, and 4
        return

    def handle_arp(self, arp, input_port):
        if arp.operation == ArpOperation.Request:
            # check if the dest IP is in our interfaces
            for intf in self.interfaces:
                if intf.ipaddr == arp.targetprotoaddr:
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

class ForwardTable(object):
    def __init__(self, net, entry_filename='forwarding_table.txt'):
        self.net = net
        self.tbl = []

        #add entries for the routers interface
        for intf in net.interfaces():
            prefix = IPv4Address(intf.ipaddr/intf.netmask)
            print(prefix)
            # there is no next hop or intf to forward on b/c we are destination
            entry = FwTblEntry(prefix, intf.netmask(), None, intf.name)
            self.tbl.append(entry)

        #add entries from the entry file
        with open(entry_filename) as file:
            lines = file.readlines()
        for line in lines:
            vals = line.split(' ')
            prefix = IPv4Address(vals[0])
            mask = IPv4Address(vals[1])
            next_hop = IPv4Address(vals[2])
            interface = vals[3]
            entry = FwTblEntry(prefix, mask, next_hop, interface)
            self.tbl.append(entry)

    def lookup(self, ipaddr):
        #TODO: Here is where we do the entire lookup
        # should return a table entry object that we can
        # then use to forward the packet
        return None


class FwTblEntry(object):
    def __init__(self, prefix, mask, next_hop, interface):
        self.prefix = prefix #Should be an IPv4Address object
        self.mask = mask     #Should be an IPv4Address object
        self.next_hop = next_hop #Should be an IPv4Address object
        self.interface = interface #Should be a string with the interface name

def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
