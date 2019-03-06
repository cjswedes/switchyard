'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *

class TableEntry():
    def __init__(self, intf, mac, timestamp):
        self.intf = intf
        self.mac = mac
        self.timestamp = timestamp

def handle_table_entry(fw_table, pkt, input_port, timestamp):
    print("GET_TABLE_ENTRY")  # : {} : {}".format(fw_table, interface))
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


def main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    fw_tbl = []  # this is where we will maintain our forward table

    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        print("~~")
        print("Packet sent from {} on input_port={} destined for: {}".format(packet[0].src, input_port, packet[0].dst))
        if packet[0].dst in mymacs:
            print("Packet intended for me. Just drop it")
        else:
            #new_src_entry = TableEntry(input_port, packet[0].src, timestamp)

            #src_entry, src_index = get_table_entry(fw_tbl, packet[0].src)
            #dst_entry, dst_index = get_table_entry(fw_tbl, packet[0].dst)

            #insert_table_entry(fw_tbl, new_src_entry, src_index, False)
            dst_known = handle_table_entry(fw_tbl, packet, input_port, timestamp)
            if dst_known:
                print("We know destination so forward")
                net.send_packet(fw_tbl[len(fw_tbl)-1].intf, packet)
            else:
                #this is simply doing the broadcast since we don't know the MAC
                for intf in my_interfaces:
                    if input_port != intf.name:
                        print("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)
    net.shutdown()
