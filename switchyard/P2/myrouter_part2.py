#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time

from switchyard.lib.packet.util import *
from switchyard.lib.userlib import *
from switchyard.lib.address import *

class Router(object):
    def __init__(self, net):
        self.net = net
        self.pkt_queue = []
        self.arp_wait_queue = []
        # Ip addresses are keys and
        self.arp_tbl = ArpTable()
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
                timestamp, input_port, pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            # simply add the packet to the queue to be processed
            if gotpkt:
                self.pkt_queue.append(PacketFwdInfo(pkt, input_port, timestamp))
                log_debug("Got a packet: {}".format(str(pkt)))

            '''if len(self.arp_wait_queue) > 0:
                pkt_info = self.arp_wait_queue.pop(0)
                # TODO fix timestamp on ARP replies to reflect need
                if (time.time() - pkt_info.arp_timestamp) > 1: #We have waited one second
                    new_pkt_info = self.handle_IPv4(pkt_info)
                    if new_pkt_info:
                        self.arp_wait_queue.append(new_pkt_info)
                else:
                    self.arp_wait_queue.append(pkt_info)'''

            if len(self.pkt_queue) > 0:
                pkt_info = self.pkt_queue.pop(0)
                if pkt_info.pkt.get_header(Arp):
                    self.handle_arp(pkt_info.pkt.get_header(Arp), input_port, timestamp)

                if pkt_info.pkt.get_header(IPv4):
                    pkt_info.pkt.get_header(IPv4).ttl = pkt_info.pkt.get_header(IPv4).ttl - 1
                    new_pkt_info = self.handle_IPv4(pkt_info)
                    if new_pkt_info:
                        self.arp_wait_queue.append(new_pkt_info)

    def handle_IPv4(self, pkt_info):
        # be careful about what to do if you need to send an arp query
        # you should check out the FAQs questions 1, 3, and 4

        # decrement TTL by 1
        # create new Ethernet header packet to be forwarded
            # dst Ethernet MAC ~ host where needs to be forwarded
            # next hop host ~
                # dst Host or IP Address on the router
        full_pkt = pkt_info.pkt
        ip_pkt = full_pkt.get_header(IPv4)
        incoming_intf = self.get_interface(pkt_info.input_port)
        entry = self.fwd_tbl.lookup(ip_pkt.dst)
        new_pkt_info = None
        #arp_entry = self.arp_tbl.lookup(ip_pkt.dst)

        if entry and entry.next_hop:
            arp_entry = self.arp_tbl.lookup(entry.next_hop)
            fwding_intf = self.get_interface(entry.interface)
            if arp_entry:
                # Create new Ethernet Header
                eth_header = Ethernet(src=fwding_intf.ethaddr,  # incoming_inft prev
                                      dst=arp_entry.MAC,
                                      ethertype=EtherType.IPv4)
                full_pkt[0] = eth_header
                self.net.send_packet(fwding_intf.name, full_pkt)
                # TODO update time of use for this ARP entry
            else:
                # send ARP request
                request = create_ip_arp_request(srchw=fwding_intf.ethaddr,
                                                srcip=fwding_intf.ipaddr,
                                                targetip=entry.next_hop)
                new_pkt_info = PacketFwdInfo(pkt=full_pkt, input_port=pkt_info.input_port,
                                             timestamp=pkt_info.timestamp,
                                             arp_attempts=pkt_info.arp_attempts + 1)
                self.net.send_packet(fwding_intf.name, request)
        elif entry and not entry.next_hop:
            arp_entry = self.arp_tbl.lookup(ip_pkt.dst)
            fwding_intf = self.get_interface(entry.interface)
            if (arp_entry):
                # Create new Ethernet Header
                eth_header = Ethernet(src=fwding_intf.ethaddr,
                                      dst=arp_entry.MAC,
                                      ethertype=EtherType.IPv4)
                full_pkt[0] = eth_header
                self.net.send_packet(fwding_intf.name, full_pkt)
            else:
                request = create_ip_arp_request(srchw=fwding_intf.ethaddr,
                                            srcip=fwding_intf.ipaddr,
                                            targetip=ip_pkt.dst)
                new_pkt_info = PacketFwdInfo(pkt=full_pkt, input_port=pkt_info.input_port,
                                             timestamp=pkt_info.timestamp,
                                             arp_attempts=pkt_info.arp_attempts + 1)
                self.net.send_packet(fwding_intf.name, request)
        '''else:  # send ARP request to all other ports
            request = create_ip_arp_request(srchw=incoming_intf.ethaddr,
                                            srcip=incoming_intf.ipaddr,
                                            targetip=ip_pkt.dst)
            for intf in self.interfaces:
                if intf.name == pkt_info.input_port:
                    continue
                self.net.send_packet(intf.name, request)'''
        return new_pkt_info

    def handle_arp(self, arp, input_port, timestamp):
        if arp.operation == ArpOperation.Request:
            # check if the dest IP is in our interfaces
            for intf in self.interfaces:
                if intf.ipaddr == arp.targetprotoaddr:
                    reply = create_ip_arp_reply(srchw=intf.ethaddr,
                                                srcip=arp.targetprotoaddr,
                                                dsthw=arp.senderhwaddr,
                                                targetip=arp.senderprotoaddr)
                    self.net.send_packet(input_port, reply)
            return  # drop packet if we dont have the IP on this router
        else:  # we received a reply
            for intf in self.interfaces:
                if intf.ipaddr == arp.targetprotoaddr:
                    # update arp table on reply where the destination is us
                    entry = ArpEntry(arp.senderprotoaddr, arp.senderhwaddr, timestamp)
                    self.arp_tbl.add(entry)
                    # self.arp_tbl[arp.targetprotoaddr] = arp.targethwaddr

            # check if reply was needed for IPv4 pkt
            self.handle_waitIPv4()
            return

    def handle_waitIPv4(self):
        # check if ARP response correlates to one of the waiting packets & process
        # TODO add timeout handle chain
        while len(self.arp_wait_queue) > 0:
            pkt_waiting = self.arp_wait_queue.pop()
            new_pkt_info = self.handle_IPv4(pkt_waiting)
            if new_pkt_info:
                self.arp_wait_queue.append(new_pkt_info)
        return

    def get_interface(self, name):
        for intf in self.interfaces:
            if intf.name == name:
                return intf
        return None


class ForwardTable(object):
    def __init__(self, net, entry_filename="forwarding_table.txt"):
        self.net = net
        self.tbl = []

        # add entries for the routers interface
        for intf in net.interfaces():
            prefix = IPv4Address(int(intf.netmask) & int(intf.ipaddr))  # already is IPv4Interface
            print(prefix)
            # there is no next hop or intf to forward on b/c we are destination
            entry = FwTblEntry(prefix, intf.netmask, None, intf.name)
            self.tbl.append(entry)

        # add entries from the entry file
        with open(entry_filename) as file:
            lines = file.readlines()
        for line in lines:
            vals = line.split()
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
        # *Should match the longest prefix first

        # find all matches and fill prefix_matches array
        prefix_matches = []

        for entry in self.tbl:
            matches = (int(entry.mask) & int(ipaddr)) == int(entry.prefix)

            if matches:
                prefix_matches.append(int(entry.mask))#netaddr.prefixlen)
            else:
                prefix_matches.append(0)

        #find match with longest prefix
        if len(prefix_matches) == 0:
            return None

        max_value = max(prefix_matches)

        if max_value == 0:
            return None
        else:
            max_index = prefix_matches.index(max_value)
            return self.tbl[max_index]


class FwTblEntry(object):
    def __init__(self, prefix, mask, next_hop, interface):
        self.prefix = prefix #Should be an IPv4Address object
        self.mask = mask     #Should be an IPv4Address object
        self.next_hop = next_hop #Should be an IPv4Address object
        self.interface = interface #Should be a string with the interface name


class PacketFwdInfo(object):
    def __init__(self, pkt, input_port, timestamp, arp_attempts=0):
        self.pkt = pkt
        self.input_port = input_port
        self.timestamp = timestamp #of the packet we received
        self.arp_attempts = arp_attempts
        self.arp_timestamp = time.time()

class ArpTable(object):
    def __init__(self):
        self.tbl = []


    def add(self, entry):
        self.tbl.append(entry)
        return


    def lookup(self, ip):
        for entry in self.tbl:
            if entry.IP == ip:
                return entry
        return None


class ArpEntry(object):
    def __init__(self, IP, MAC, time_stamp):
        self.IP = IP
        self.MAC = MAC
        self.time_stamp = time_stamp  # Should be an int


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
