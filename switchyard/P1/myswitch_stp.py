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
    '''
    Finds initial root and creates packet to be flooded
    :param interfaces: known interfaces/ports
    :return: curr (current root) pkt (packet to be flooded)
    '''
    print("Initializing!!!")
    #find smallest mac in interfaces for id
    curr = interfaces[0].ethaddr.toStr() if len(interfaces) > 0 else None
    for intf in interfaces:
        if intf.ethaddr.toStr() < curr:
            curr = intf.ethaddr.toStr()

    #create stp packet, ethernet src and dst dont matter
    pkt = mk_stp_pkt(root_id=curr, hops=0) # root expects string not EthAddr object
    print("id: {} packet: {}".format(curr, bool(pkt)))
    return curr, pkt

def handle_stp(packet, stp_root, fw_mode):
    stp_intf = stp_root
    return stp_root, stp_intf

'''
This is run every two seconds, by the timer.
it should be stopped if you are no longer the root
'''
def send_stp(root_id, hops, my_interfaces, fw_mode, net):
    pkt = mk_stp_pkt(root_id=root_id, hops=hops)
    for intf in my_interfaces:
        print("Flooding STP with root {} and steps {}".format(pkt[1].root, pkt[1].hops_to_root))
        net.send_packet(intf.name, pkt)
        fw_mode[intf.name]=True
    return

def main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    fw_mode = {intf.name: True for intf in my_interfaces}
    root_intf = None #none indicates we think we are the root
    fw_tbl = []  # this is where we will maintain our forward table

    stp_root, packet = initialize_stp(my_interfaces)

    # flood stp packet to all links
    for intf in my_interfaces:
        print("Flooding STP with root {} and steps {}".format(packet.get_header_by_name('SpanningTreeMessage').root,
                                                              packet.get_header_by_name('SpanningTreeMessage').hops_to_root))
        net.send_packet(intf.name, packet)

    # start timer to automatically send pkt every 2 seconds
    sending_spt = RepeatedTimer(interval=2, function=send_stp, root_id=stp_root, hops=0, fw_mode=fw_mode, net=net,
                                my_interfaces=my_interfaces)
    while True:
        try:
            #stop sending stp if we are no longer the root
            if root_intf:
                a=1
                sending_spt.stop()
            else:
                a=1 #this is hear to avoid syntax failures
                sending_spt.start()
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        print("~~")
        print("Packet sent from {} on input_port={} destined for: {}".format(packet[0].src, input_port, packet[0].dst))
        if packet.get_header_by_name('SpanningTreeMessage'):
            stp_root, root_intf = handle_stp(packet, stp_root, fw_mode) #modifies fw_mode
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
