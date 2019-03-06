'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *
from threading import Timer
from spanningtreemessage import SpanningTreeMessage


class RepeatedTimer(object):
    def __init__(self, interval, function, *args, **kwargs):
        self._timer     = None
        self.interval   = interval
        self.function   = function
        self.args       = args
        self.kwargs     = kwargs
        self.is_running = False
        self.start()

    def _run(self):
        self.is_running = False
        self.start()
        self.function(*self.args, **self.kwargs)

    def start(self):
        if not self.is_running:
            self._timer = Timer(self.interval, self._run)
            self._timer.start()
            self.is_running = True

    def stop(self):
        self._timer.cancel()
        self.is_running = False


class TableEntry():
    def __init__(self, intf, mac, timestamp):
        self.intf = intf
        self.mac = mac
        self.timestamp = timestamp

def mk_stp_pkt(root_id, hops, hwsrc="20:00:00:00:00:01", hwdst="ff:ff:ff:ff:ff:ff"):
    spm = SpanningTreeMessage(root=root_id, hops_to_root=hops)
    Ethernet.add_next_header_class(EtherType.SLOW, SpanningTreeMessage)
    pkt = Ethernet(src=hwsrc,
                   dst=hwdst,
                   ethertype=EtherType.SLOW) + spm
    xbytes = pkt.to_bytes()
    p = Packet(raw=xbytes)
    return p

def handle_table_entry(fw_table, pkt, input_port, timestamp):
    src_exists = False
    dst_exists = False
    for i in range(len(fw_table)):
        if fw_table[i].mac == pkt[0].src:
            src_exists = True
            index = i
    if src_exists:
        if input_port != fw_table[index]:
            fw_table[index].intf = input_port
            fw_table[index].timestamp = timestamp
        #dst decision
        for i in range(len(fw_table)):
            if fw_table[i].mac == pkt[0].dst:
                dst_exists = True
                index = i
        if dst_exists:
            fw_table.append(fw_table.pop(index))
        return dst_exists
    else:
        if len(fw_table) < 5:
            fw_table.append(TableEntry(intf=input_port, mac=pkt[0].src, timestamp=timestamp))
            #dst decision
            for i in range(len(fw_table)):
                if fw_table[i].mac == pkt[0].dst:
                    dst_exists = True
                    index = i
            if dst_exists:
                fw_table.append(fw_table.pop(index))
            return dst_exists
        else:
            fw_table.pop(0)
            fw_table.append(TableEntry(intf=input_port, mac=pkt[0].src, timestamp=timestamp))
            # dst decision
            for i in range(len(fw_table)):
                if fw_table[i].mac == pkt[0].dst:
                    dst_exists = True
                    index = i
            if dst_exists:
                fw_table.append(fw_table.pop(index))
            return dst_exists


def broadcast(interfaces, packet, input_port, net, fw_mode):
    for intf in interfaces:
        if input_port != intf.name and fw_mode[intf.name]:
            net.send_packet(intf.name, packet)


def validate_packet(packet):
    if not packet.get_header_by_name('Ethernet'):
        return False

    if packet.get_header_by_name('SpanningTreeMessage'):
        a=1
        # Tests for header values
        if packet.get_header_by_name('SpanningTreeMessage').hops_to_root < 0:
            return False
    return True


def initialize_stp(interfaces):
    '''
    Finds initial root and creates packet to be flooded
    :param interfaces: known interfaces/ports
    :return: curr (current root) pkt (packet to be flooded)
    '''
    #find smallest mac in interfaces for id
    curr = interfaces[0].ethaddr.toStr() if len(interfaces) > 0 else None
    for intf in interfaces:
        if intf.ethaddr.toStr() < curr:
            curr = intf.ethaddr.toStr()

    #create stp packet, ethernet src and dst dont matter
    pkt = mk_stp_pkt(root_id=curr, hops=0, hwsrc=curr) # root expects string not EthAddr object
    return curr, pkt


def send_stp(root_id, hops, my_interfaces, fw_mode, net):
    '''
    This is run every two seconds, by the timer.
    it should be stopped if you are no longer the root
    '''

    for intf in my_interfaces:
        pkt = mk_stp_pkt(root_id=root_id, hops=hops, hwsrc=root_id)
        net.send_packet(intf.name, pkt)
        fw_mode[intf.name]=True
    return


def main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    fw_mode = {intf.name: True for intf in my_interfaces}
    fw_tbl = []  # this is where we will maintain our forward table

    # Switch STP variables
    stp_root, packet = initialize_stp(my_interfaces)     # stp_root = root id
    this_id = stp_root
    root_intf = None  # none indicates we think we are the root
    this_hops_to_root = 0
    time_of_last_stp = 0

    # flood stp packet to all links at startup
    for intf in my_interfaces:
       net.send_packet(intf.name, packet)

    # start timer to automatically send pkt every 2 seconds
    sending_stp = RepeatedTimer(interval=2, function=send_stp, root_id=stp_root, hops=0, fw_mode=fw_mode, net=net,
                                my_interfaces=my_interfaces)
    while True:
        try:
            # stop sending stp if we are no longer the root
            if root_intf is not None:
                a=1
                sending_stp.stop()
            else:
                a=1 # this is here to avoid syntax failures
                sending_stp.start()
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        if not validate_packet(packet):
            # DROP
            continue
        elif packet.get_header_by_name('SpanningTreeMessage'):
            # HANDLE STP PACKET
            time_of_last_stp = timestamp

            packet_header = packet.get_header_by_name('SpanningTreeMessage')

            # First determine if root remains
            if packet_header.root < EthAddr(stp_root):
                stp_root_new = packet_header.root
                root_intf = input_port
            else:
                stp_root_new = stp_root

            if stp_root_new != stp_root:
                # increment hops by 1 of packet
                packet.get_header_by_name('SpanningTreeMessage').hops_to_root = packet_header.hops_to_root + 1
                # update packet info {record incr hops, intf set to forwarding mode}
                this_hops_to_root = packet.get_header_by_name('SpanningTreeMessage').hops_to_root
                fw_mode[input_port] = True
                stp_root = stp_root_new
                if stp_root == this_id:
                    root_intf = None
                else:
                    root_intf = input_port
                # forward all packets on except input
                packet[0].src = this_id
                broadcast(my_interfaces, packet, input_port, net, fw_mode)

            elif packet_header.root == stp_root:
                if packet_header.hops_to_root + 1 < this_hops_to_root:
                    # increment hops by 1
                    packet.get_header_by_name('SpanningTreeMessage').hops_to_root = packet_header.hops_to_root + 1
                    # update packet info {intf set to forwarding mode, record incr hops}
                    this_hops_to_root = packet.get_header_by_name('SpanningTreeMessage').hops_to_root
                    fw_mode[input_port] = True

                    # forward all packets on except root intf
                    packet[0].src = this_id
                    broadcast(my_interfaces, packet, input_port, net, fw_mode)

                elif packet_header.hops_to_root + 1 > this_hops_to_root:
                    # IGNORE
                    continue
                elif packet_header.hops_to_root + 1 == this_hops_to_root: # and input_port != root_intf:
                    # set interface of arrival to blocking mode
                    fw_mode[input_port] = False

        elif packet[0].dst in mymacs:
            # Packet intended for me. Just drop it
            continue
        else:
            dst_known = handle_table_entry(fw_tbl, packet, input_port, timestamp)

            if dst_known:
                # We know the destination so forward
                net.send_packet(fw_tbl[len(fw_tbl)-1].intf, packet)
            else:
                # this is simply doing the broadcast since we don't know the MAC
                broadcast(my_interfaces, packet, input_port, net, fw_mode)
    net.shutdown()
