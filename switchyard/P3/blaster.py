#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from random import randint
import time

class SenderWindow():
    '''
    Each entry in the window list will be a tuple of the form(seq_num, ACK'd, send time, pkt)
    Just an integer, boolean , timestamp and packet to know which pkts have been ACK'd and
    what packets need to be resent. We need to store all the packets so they can be ressent if necessary

    We will keep track of LHS and RHS just by knowing the 1st and last
    element of the window array.

    This class has a function to handle a received ACK
    '''
    def __init__(self, size, timeout):
        self.window = []
        self.size = size
        self.timeout = timeout

    def window_full(self):
        return len(self.window) >= self.size

    def handle_ack(self, seq_num):
        for index, entry in enumerate(self.window):
            if entry[0] == seq_num:
                entry[1] = True
                if index == 0:  # This is the lowest seq number
                    self.window.pop(0)


    def handle_send(self, seq_num, packet):
        '''
        This adds packets to the window after they have already been sent
        :return True or false if the packet was sent.
        '''
        if self.window_full():
            return False
        self.window.append((seq_num, False, time.time(), packet))
        return True

    def check_timeouts(self):
        '''
        This checks each timer and will resend the packet if necessary
        :return: nothing
        '''
        for index, entry in enumerate(self.window):
            if time.time() - entry[2] > self.timeout:
                log_debug('Resending packet num: ' + entry[0])
                self.window[index][2] = time.time()  # update the timer
                #TODO: resend packet
        return None


def print_output(total_time, num_ret, num_tos, throughput, goodput):
    print("Total TX time (s): " + str(total_time))
    print("Number of reTX: " + str(num_ret))
    print("Number of coarse TOs: " + str(num_tos))
    print("Throughput (Bps): " + str(throughput))
    print("Goodput (Bps): " + str(goodput))

def create_raw_packet_header(type, pkt_num):
    return bytes(str(type) + ' ' + str(pkt_num), 'utf8')

def extract_sequence_num(data):
    string_data = str(data)
    try:
        num = int(string_data.split().pop(-1))
    except:
        print('error in blastee extracting the sequence number')
        assert False

    return num

def switchy_main(net):
    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]

    # Parsing the arguments file
    with open('blaster_params.txt') as params:
        args = params.readline().split()
    if len(args) < 10:
        print('Arguments issue in blaster')
        assert False
    NUM_PKTS = int(args[1])
    LENGTH = int(args[3])
    SENDER_WINDOW = int(args[5])
    TIMEOUT = int(args[7])
    RECV_TIMEOUT = int(args[9])

    sw = SenderWindow(SENDER_WINDOW, TIMEOUT)
    while True:
        gotpkt = True
        try:
            #Timeout value will be parameterized!
            timestamp,dev,pkt = net.recv_packet(timeout=0.15)
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        sw.check_timeouts()

        if gotpkt:
            log_debug("I got a packet")
            # TODO: handle the ACK
        else:
            log_debug("Didn't receive anything")

            '''
            Creating the headers for the packet
            '''
            pkt = Ethernet() + IPv4() + UDP()
            pkt[1].protocol = IPProtocol.UDP

            '''
            Do other things here and send packet
            '''

    net.shutdown()
