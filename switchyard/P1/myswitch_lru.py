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

def get_table_entry(fw_table, address):
    # TODO return the table entry if it exists
    #  should return the index of the entry or false if there isn't an entry
    #  Return: {entry, index}
    print("GET_TABLE_ENTRY") # : {} : {}".format(fw_table, interface))
    for i in range(len(fw_table)):
        #print("   fw_table[{}]={}".format(i,fw_table[i]))
        if fw_table[i].mac == address:
            return fw_table[i],i

    return False, -1

def insert_table_entry(fw_table, entry: TableEntry, index_to_remove):
    # TODO: this maintains the LRU format of the table
    #  index_to_remove = -1 if not in table, >0 if valid entry
    #  Return: none
    print("INSERT_TABLE_ENTRY : index={} : len={}".format(index_to_remove, len(fw_table)))
    if index_to_remove >= 0:
        #Replace Index
        fw_table.insert(index_to_remove, entry)
    else:
        #Add Entry (replace LRU if full, else add)
        fw_table.append(entry)
    return


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

        print("~~")
        print("Packet sent from {} on input_port={} destined for: {}".format(packet[0].src, input_port, packet[0].dst))
        if packet[0].dst in mymacs:
            print("Packet intended for me. Just drop it")
        else:
            new_entry = TableEntry(input_port, packet[0].src, timestamp)

            src_entry, src_index = get_table_entry(fw_tbl, packet[0].src)
            dst_entry, dst_index = get_table_entry(fw_tbl, packet[0].dst)

            insert_table_entry(fw_tbl, new_entry, src_index)

            if dst_entry :
                print("We know destination so forward")
                net.send_packet(dst_entry.intf, packet)
            else:
                #this is simply doing the broadcast since we don't know the MAC
                for intf in my_interfaces:
                    if input_port != intf.name:
                        print("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)
    net.shutdown()
