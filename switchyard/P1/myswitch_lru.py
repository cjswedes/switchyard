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

def get_table_entry(fw_table, interface):
    return
    #TODO return the table entry if iit exists
    # should return the index of the entry or false if there isn't an entry


def insert_table_entry(fw_table, entry: TableEntry, index_to_remove):
    return
    #TODO: this maintains the LRU format of the tablle

def main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    fw_tbl = [] #this is where we will maintain our forward table

    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        print("Packet sent from {} on input_port={} destined for: {}".format(packet[0].src, input_port, packet[0].dst))
        if packet[0].dst in mymacs:
            print("Packet intended for me. Just drop it")
        else:
            entry, index = get_table_entry(fw_tbl, input_port)
            new_entry = TableEntry(input_port, packet[0].src, timestamp)
            if entry and entry.mac == packet[0].dst:
                print("We know destination so forward")
                net.send_packet(input_port, packet)
                insert_table_entry(fw_tbl, new_entry, index)
                continue
            else:
                insert_table_entry(fw_tbl, new_entry, index)

            #this is simply doing the broadcast since we dont know the MAC
            for intf in my_interfaces:
                if input_port != intf.name:
                    print("Flooding packet {} to {}".format(packet, intf.name))
                    net.send_packet(intf.name, packet)
    net.shutdown()
