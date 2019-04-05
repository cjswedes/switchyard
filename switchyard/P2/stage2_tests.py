import struct

from dynamicroutingmessage import DynamicRoutingMessage
from ipaddress import IPv4Address
from switchyard.lib.userlib import *
from switchyard.lib.packet import *


def mk_dynamic_routing_packet(ethdst, advertised_prefix, advertised_mask,
                               next_hop):
    drm = DynamicRoutingMessage(advertised_prefix, advertised_mask, next_hop)
    Ethernet.add_next_header_class(EtherType.SLOW, DynamicRoutingMessage)
    pkt = Ethernet(src='00:00:22:22:44:44', dst=ethdst,
                   ethertype=EtherType.SLOW) + drm
    xbytes = pkt.to_bytes()
    p = Packet(raw=xbytes)
    return p

def mk_pkt(hwsrc, hwdst, ipsrc, ipdst, reply=False, ttl = 64):
    ether = Ethernet(src=hwsrc, dst=hwdst, ethertype=EtherType.IP)
    ippkt = IPv4(src=ipsrc, dst=ipdst, protocol=IPProtocol.ICMP, ttl=ttl)
    icmppkt = ICMP()
    if reply:
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt.icmptype = ICMPType.EchoRequest
    return ether + ippkt + icmppkt


def router_tests():
    s = TestScenario("Basic functionality testing for DynamicRoutingMessage")

    # Initialize switch with 3 ports.
    s.add_interface('router-eth0', '10:00:00:00:00:01', ipaddr = '192.168.1.1', netmask = '255.255.255.252')
    s.add_interface('router-eth1', '10:00:00:00:00:02', ipaddr = '10.10.0.1', netmask = '255.255.0.0')
    s.add_interface('router-eth2', '10:00:00:00:00:03', ipaddr = '172.16.42.1', netmask = '255.255.255.0')
    s.add_interface('router-eth3', '10:00:00:00:00:04', ipaddr = '111.111.111.1', netmask='255.255.192.0')


    # 1   IP packet to be forwarded to 172.16.42.2 should arrive on
    #     router-eth0
    #         Expected event: recv_packet Ethernet
    #         10:00:00:00:00:03->30:00:00:00:00:01 IP | IPv4
    #         192.168.1.100->172.16.42.2 ICMP | ICMP EchoRequest 0 42 (0
    #         data bytes) on router-eth0

    packet = mk_pkt(hwsrc = '10:00:00:00:00:03', hwdst =  '30:00:00:00:00:01', ipsrc  = '192.168.1.100', ipdst = '172.16.42.2')
    s.expect(PacketInputEvent("router-eth0", packet), "IP packet to be forwarded to 172.16.42.2 should arrive on router-eth0")

    # 2   Router should send ARP request for 172.16.42.2 out router-
    #     eth2 interface
    #         Expected event: send_packet(s) Ethernet
    #         10:00:00:00:00:03->ff:ff:ff:ff:ff:ff ARP | Arp
    #         10:00:00:00:00:03:172.16.42.1 ff:ff:ff:ff:ff:ff:172.16.42.2
    #         out router-eth2

    arp_request  = create_ip_arp_request('10:00:00:00:00:03', '172.16.42.1', '172.16.42.2')
    s.expect(PacketOutputEvent("router-eth2", arp_request), "Router should send ARP request for 172.16.42.2 out router-eth2 interface")

    # 3   Router should receive ARP response for 172.16.42.2 on
    #     router-eth2 interface
    #         Expected event: recv_packet Ethernet
    #         30:00:00:00:00:01->10:00:00:00:00:03 ARP | Arp
    #         30:00:00:00:00:01:172.16.42.2 10:00:00:00:00:03:172.16.42.1
    #         on router-eth2

    arp_response = create_ip_arp_reply('30:00:00:00:00:01', '10:00:00:00:00:03',
                                       '172.16.42.2', '172.16.42.1')
    s.expect(PacketInputEvent("router-eth2", arp_response), "Router should receive ARP response for 172.16.42.2 on router-eth2 interface")


    # 4   IP packet should be forwarded to 172.16.42.2 out router-eth2
    #         Expected event: send_packet(s) Ethernet
    #         10:00:00:00:00:03->30:00:00:00:00:01 IP | IPv4
    #         192.168.1.100->172.16.42.2 ICMP | ICMP EchoRequest 0 42 (0
    #         data bytes) out router-eth2

    packet = mk_pkt(hwsrc='10:00:00:00:00:03', hwdst='30:00:00:00:00:01', ipsrc='192.168.1.100', ipdst='172.16.42.2', ttl=63)
    s.expect(PacketOutputEvent("router-eth2", packet), "IP packet should be forwarded to 172.16.42.2 out router-eth2")


    # 1   IP packet to be forwarded to 172.16.42.2 should arrive on
    #     router-eth0
    #         Expected event: recv_packet Ethernet
    #         10:00:00:00:00:03->30:00:00:00:00:01 IP | IPv4
    #         192.168.1.100->172.16.42.2 ICMP | ICMP EchoRequest 0 42 (0
    #         data bytes) on router-eth0

    packet = mk_pkt(hwsrc = '10:00:00:00:00:03', hwdst =  '30:00:00:00:00:01', ipsrc  = '192.168.1.100', ipdst = '172.16.42.2')
    s.expect(PacketInputEvent("router-eth0", packet), "IP packet to be forwarded to 172.16.42.2 should arrive on router-eth0")


    # 4   IP packet should be forwarded to 172.16.42.2 out router-eth2
    #         Expected event: send_packet(s) Ethernet
    #         10:00:00:00:00:03->30:00:00:00:00:01 IP | IPv4
    #         192.168.1.100->172.16.42.2 ICMP | ICMP EchoRequest 0 42 (0
    #         data bytes) out router-eth2

    packet = mk_pkt(hwsrc='10:00:00:00:00:03', hwdst='30:00:00:00:00:01', ipsrc='192.168.1.100', ipdst='172.16.42.2', ttl=63)
    s.expect(PacketOutputEvent("router-eth2", packet), "IP packet should be forwarded to 172.16.42.2 out router-eth2")

    # inject ip packet not in arp table
    # inject ip packet that is in arp table
    # receive arp request
    # receive ip packeet (the second one)
    # respond to arp request
    # receive ip packet (the first on)
    packet_arp = mk_pkt(hwsrc='10:00:00:00:00:03', hwdst='30:00:00:00:00:01', ipsrc='192.168.1.100', ipdst='172.16.128.3')
    s.expect(PacketInputEvent("router-eth2", packet_arp), "should receive IP packet requiring arp resolution to be forwarded out router-eth1")

    arp_request = create_ip_arp_request('10:00:00:00:00:02', '10.10.0.1', '10.10.0.254')
    s.expect(PacketOutputEvent("router-eth1", arp_request), "should receive arp request to resolve uknown ethaddr for 172.16.128.3")

    packet_noarp = mk_pkt(hwsrc='10:00:00:00:00:03', hwdst='30:00:00:00:00:01', ipsrc='192.168.1.100', ipdst='172.16.42.2')
    s.expect(PacketInputEvent("router-eth2", packet_noarp), "IP packet not requiring arp resolution to be forwarded out router-eth2")
    packet_noarp = mk_pkt(hwsrc='10:00:00:00:00:03', hwdst='30:00:00:00:00:01', ipsrc='192.168.1.100', ipdst='172.16.42.2', ttl=63)
    s.expect(PacketOutputEvent("router-eth2", packet_noarp), "Packet with arp mapping should be forwarded out router-eth2")
    arp_response = create_ip_arp_reply('aa:aa:00:00:00:02', '10:00:00:00:00:03',
                                       '10.10.0.254', '172.16.42.1')
    s.expect(PacketInputEvent("router-eth1", arp_response),
             "Router should receive ARP response for 172.16.128.3 on router-eth1 interface")
    packet_arp = mk_pkt(hwsrc='10:00:00:00:00:02', hwdst='aa:aa:00:00:00:02', ipsrc='192.168.1.100', ipdst='172.16.128.3', ttl=63)
    s.expect(PacketOutputEvent("router-eth1", packet_arp), "packet that was resolved with arp should be forwarded")


    # inject ip packet that doesn't haave an entry in the fwd table
    # it should drop
    packet = mk_pkt(hwsrc='10:00:00:00:00:03', hwdst='30:00:00:00:00:01', ipsrc='192.168.1.100', ipdst='128.128.128.128')
    s.expect(PacketInputEvent("router-eth0", packet), 'Receive packet without an entry in forward table. Do nothing')

    # inject ip packet, has not arp entry
    # wait for 3 arp requests
    # the packet should be dropped
    # this doesn't test timing, just number of arp requests sents
    packet_arp = mk_pkt(hwsrc='10:00:00:00:00:03', hwdst='30:00:00:00:00:01', ipsrc='192.168.1.100',
                        ipdst='99.99.9.1')
    # seems like this packet is getting dropped for some reason, but I dont know why
    # it could have to do with how I added the entry to the forwarding_table.txt
    s.expect(PacketInputEvent("router-eth2", packet_arp),
             "should receive IP packet requiring arp resolution to be forwarded out router-eth1")

    arp_request = create_ip_arp_request('10:00:00:00:00:04', '111.111.111.1', '22.22.22.22')
    s.expect(PacketOutputEvent("router-eth3", arp_request),
             "should receive arp request to resolve unknown next hop for 99.99.9.1")
    s.expect(PacketOutputEvent('router-eth3', arp_request), 'receive arp reqeuest 2')
    s.expect(PacketOutputEvent('router-eth3', arp_request), 'receive arp reqeuest 3')


    return s

scenario = router_tests()