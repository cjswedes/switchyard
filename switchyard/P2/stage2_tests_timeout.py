import struct
import time

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

    #time.sleep(1)
    arp_request  = create_ip_arp_request('10:00:00:00:00:03', '172.16.42.1', '172.16.42.2')
    s.expect(PacketOutputEvent("router-eth2", arp_request), "Router should send ARP request for 172.16.42.2 out router-eth2 interface")


    # 2   Router should send ARP request for 172.16.42.2 out router-
    #     eth2 interface
    #         Expected event: send_packet(s) Ethernet
    #         10:00:00:00:00:03->ff:ff:ff:ff:ff:ff ARP | Arp
    #         10:00:00:00:00:03:172.16.42.1 ff:ff:ff:ff:ff:ff:172.16.42.2
    #         out router-eth2

    packet = mk_pkt(hwsrc = '10:00:00:00:00:02', hwdst =  '30:00:00:00:00:04', ipsrc  = '192.168.1.100', ipdst = '172.16.42.2')
    s.expect(PacketInputEvent("router-eth0", packet), "IP packet to be forwarded to 172.16.42.2 should arrive on router-eth0")


    #time.sleep(1)
    arp_request  = create_ip_arp_request('10:00:00:00:00:03', '172.16.42.1', '172.16.42.2')
    s.expect(PacketOutputEvent("router-eth2", arp_request), "Router should send ARP request for 172.16.42.2 out router-eth2 interface")

    # 2   Router should send ARP request for 172.16.42.2 out router-
    #     eth2 interface
    #         Expected event: send_packet(s) Ethernet
    #         10:00:00:00:00:03->ff:ff:ff:ff:ff:ff ARP | Arp
    #         10:00:00:00:00:03:172.16.42.1 ff:ff:ff:ff:ff:ff:172.16.42.2
    #         out router-eth2

    packet = mk_pkt(hwsrc = '10:00:00:00:00:02', hwdst =  '30:00:00:00:00:04', ipsrc  = '192.168.1.100', ipdst = '172.16.42.2')
    s.expect(PacketInputEvent("router-eth0", packet), "IP packet to be forwarded to 172.16.42.2 should arrive on router-eth0")

    #time.sleep(1)
    arp_request  = create_ip_arp_request('10:00:00:00:00:03', '172.16.42.1', '172.16.42.2')
    s.expect(PacketOutputEvent("router-eth2", arp_request), "Router should send ARP request for 172.16.42.2 out router-eth2 interface")

    packet = mk_pkt(hwsrc = '10:00:00:00:00:02', hwdst =  '30:00:00:00:00:02', ipsrc  = '192.168.1.100', ipdst = '172.16.42.2')
    s.expect(PacketInputEvent("router-eth0", packet), "IP packet to be forwarded to 172.16.42.2 should arrive on router-eth0")



    s.expect(PacketInputTimeoutEvent(packet), "No Packets should be sent or received")

    return s

scenario = router_tests()