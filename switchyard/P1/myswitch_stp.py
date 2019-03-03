'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *
from myswitchstp_test_release import mk_stp_pkt
from threading import Timer

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

def get_table_entry(fw_table, address):
    '''
    should return the index of the entry or false if there isn't an entry
    Return: {entry, index}
    '''
    print("GET_TABLE_ENTRY") # : {} : {}".format(fw_table, interface))
    for i in range(len(fw_table)):
        if fw_table[i].mac == address:
            return fw_table[i],i

    return False, -1

def insert_table_entry(fw_table, entry: TableEntry, index, ifDst):
    '''Parameters:
           index: -1 if not in table, else 0-4
           ifDst: automatically Most Recently Used if dst, False if src
      LRU: [Least Recent, ... ,Most Recent]
      Return: none
    '''
    print("INSERT_TABLE_ENTRY : index={} : len={}".format(index, len(fw_table)))

    if index >= 0:
        # Update table
        if ifDst:
            fw_table.pop(0)
            fw_table.append(entry)
        else:
            fw_table.pop(index)
            fw_table[index].intf = entry.intf
    elif index == -1:
        # Add New Entry
        if len(fw_table) <= 5:
            fw_table.append(entry)
        else:
            # Remove LRU & Add
            fw_table.pop(0)
            fw_table.append(entry)
    else:
        print("ERROR")
    return

def initialize_stp(interfaces):
    print("Initializing!!!")
    #find smallest mac in interfaces for id
    curr = interfaces[0].ethaddr.toStr() if len(interfaces) > 0 else None
    for intf in interfaces:
        if intf.ethaddr.toStr() < curr:
            curr = intf.ethaddr.toStr()

    #create stp packet, ethernet src and dst dont matter
    pkt = mk_stp_pkt(root_id=curr, hops=0) # root expects string not EthAddr object
    print("id: {}\npacket: {}".format(curr, bool(pkt)))
    return curr, pkt

def handle_stp(pkt: Packet, spt_root, fw_mode, root_intf, input_intf):
    '''
        When a node receives a spanning tree packet it examines the root attribute:

    If the id in the received packet is smaller than the id that the node currently thinks is the root, the id in the received packet becomes the new root. The node should then forward the packet out all interfaces except for the one on which the packet was received. Prior to forwarding, the number of hops to the root should be incremented by 1. The interface on which the spanning tree message arrived must be set to forwarding mode if it is not already set, and the number of hops to the root (the value in the received packet + 1) must be recorded.
    If the id in the received packet is the same as the id that the node currently thinks is the root, it examines the number of hops to the root value:
        If the number of hops to the root + 1 is less than the value that the switch has stored, it sets the interface on which this packet has arrived to forwarding mode (If it is not already set). The switch should then forward the spanning tree message out all interfaces except the one on which the message arrived, incrementing the number of hops to the root by 1 prior to forwarding.
        If the number of hops to the root + 1 is greater than the value that the switch has stored, just ignore the packet and do nothing
        If the number of hops to the root + 1 equal to the value that the switch has stored, but is different from the initial port it got this message from, it should set the interface on which this packet arrived to blocking mode.
    Lastly, the learning switch forwarding algorithm changes a bit in the context of a spanning tree. Instead of flooding a frame with an unknown destination Ethernet address out every port (except the one on which the frame was received), a switch only floods a frame out every port (again, except the input port) if and only if the interface is in forwarding mode.

    :param pkt:
    :return:
    '''
    #extract SpanningTreeMessage
    msg = pkt.get_header_by_name('SpanningTreeMesssage')

    #compare ids
    if msg.root < spt_root:
        spt_root = msg.root
        root_int = input_intf #where do we account for the case of there being another root node, and we discover that we should be the root node. Can this ever happen?
        fwd_spt_pkt = mk_stp_pkt(root_id=spt_root, hops=msg.hops_to_root+1)
        fw_mode[root_int] = True
        #need to send pkt and record the number of hops
    return None, None

'''
This is run every two seconds, by the timer.
it should be stopped if you are no longer the root
'''
def send_spt(root_id, hops, my_interfaces, fw_mode, net):
    pkt = mk_stp_pkt(root_id=root_id, hops=hops)
    for intf in my_interfaces:
        print("Flooding STP with root {} and steps {}".format(pkt[1].root, pkt[1].hops_to_root))
        net.send_packet(intf.name, pkt)
        fw_mode[intf.name]=True

def spt_send_if_root(sending_spt, root_intf):
    #stop sending stp if we are no longer the root
    if root_intf:
        a=1
        sending_spt.stop()
    else:
        a=1 #this is hear to avoid syntax failures
        #sending_spt.start()

def main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    fw_mode = {intf.name: True for intf in my_interfaces}
    root_intf = None #none indicates we think we are the root, otherwise the the interface that has the root
    fw_tbl = []  # this is where we will maintain our forward table

    spt_root, packet = initialize_stp(my_interfaces)

    # flood stp packet to all links
    for intf in my_interfaces:
        print("Flooding STP with root {} and steps {}".format(packet.get_header_by_name('SpanningTreeMessage').root,
                                                              packet.get_header_by_name('SpanningTreeMessage').hops_to_root))
        net.send_packet(intf.name, packet)

    # start timer to automatically send pkt every 2 seconds
    sending_timer = RepeatedTimer(2, send_spt, root_id=spt_root,
                                  hops=0, fw_mode=fw_mode, net=net,
                                  my_interfaces=my_interfaces)
    while True:
        try:
            spt_send_if_root(sending_timer, root_intf)

            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        print("~~")
        print("Packet sent from {} on input_port={} destined for: {}".format(packet[0].src, input_port, packet[0].dst))
        if packet.get_header_by_name('SpanningTreeMessage'):
            stp_root, root_intf  = handle_stp(packet, stp_root=stp_root, fw_mode=fw_mode,
                                              root_intf=root_intf, input_intf=input_port) #modifies fw_mode
        elif packet[0].dst in mymacs:
            print("Packet intended for me. Just drop it")
        else:
            new_src_entry = TableEntry(input_port, packet[0].src, timestamp)

            src_entry, src_index = get_table_entry(fw_tbl, packet[0].src)
            dst_entry, dst_index = get_table_entry(fw_tbl, packet[0].dst)

            insert_table_entry(fw_tbl, new_src_entry, src_index, False)

            if dst_entry:
                print("We know destination so forward")
                net.send_packet(dst_entry.intf, packet)
                #update dst entry in table
                dst_entry.timestamp = timestamp
                insert_table_entry(fw_tbl, dst_entry, dst_index, True)
            else:
                #this is simply doing the broadcast since we don't know the MAC
                for intf in my_interfaces:
                    if input_port != intf.name:
                        print("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)
    net.shutdown()