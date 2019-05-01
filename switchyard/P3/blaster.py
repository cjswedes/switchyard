#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from switchyard.lib import logging
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
        log_debug('Sender window initialized')

    def window_full(self):
        return len(self.window) >= self.size

    def is_empty(self):
        return len(self.window) == 0

    def handle_ack(self, seq_num):
        for index, entry in enumerate(self.window):
            if entry[0] == seq_num:
                entry[1] = True
                if index == 0:  # This is the lowest seq number
                    self.window.pop(0)


    def handle_send(self, net, intf, seq_num, packet):
        '''
        This adds packets to the window after they have already been sent
        :return True or false if the packet was sent.
        '''
        if self.window_full():
            return False
        net.send_packet(intf, packet)
        log_debug('sending_packet with seq_num: {}'.format(seq_num))

        self.window.append((seq_num, False, time.time(), packet))
        return True

    def check_timeouts(self, net, resend_intf):
        '''
        This checks each timer and will resend the packet if necessary
        :return: nothing
        '''
        log_debug("Checking Timeouts")
        for index, entry in enumerate(self.window):
            if time.time() - entry[2] > self.timeout:
                log_debug('Resending packet num: ' + entry[0])
                self.window[index][2] = time.time()  # update the timer
                # resend the packet
                net.send_packet(resend_intf.name, entry[3])
        return None


def print_output(total_time, num_ret, num_tos, throughput, goodput):
    print("Total TX time (s): " + str(total_time))
    print("Number of reTX: " + str(num_ret))
    print("Number of coarse TOs: " + str(num_tos))
    print("Throughput (Bps): " + str(throughput))
    print("Goodput (Bps): " + str(goodput))

def create_raw_packet_header(type, pkt_num):
    res = bytes('{} {}'.format(type, pkt_num), 'utf8')
    log_debug('created SYN header: {}'.format(res))
    return res

def extract_sequence_num(raw_header):
    # print("rawheader= {}".format(raw_header.data))
    # print("converttostr= {}".format(str(raw_header.data)))
    try:
        # print('middle= {}'.format(str(raw_header.data).replace("'", "").split(' ')))
        num = str(raw_header.data).replace("'", "").split(' ').pop(-1)
    except:
        print('error in blastee extracting the sequence number')
        assert False

    return num

def switchy_main(net):
    logging.setup_logging(True)

    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]

    # variables to kept track of for ending output
    START_TIME = time.time()
    NUM_RETX = 0
    NUM_COARSE_TO = 0
    THROUGH_PUT = 0
    GOOD_PUT = 0
    num_acks = 0

    BLASTEE_ETHADDR = EthAddr('20:00:00:00:00:01')
    BLASTER_ETHADDR = EthAddr('10:00:00:00:00:01')
    MIDDLEBOX_ETHADDR = EthAddr('40:00:00:00:00:01')


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

    log_debug('Numpkt={}, length={}, sw={}, timeout={} recv_timeout={}'.format(NUM_PKTS, LENGTH,
                                                                           SENDER_WINDOW, TIMEOUT, RECV_TIMEOUT))
    NEXT_SEND_SEQ = 1

    sw = SenderWindow(SENDER_WINDOW, TIMEOUT)
    while True:
        gotpkt = True
        if num_acks == NUM_PKTS:
            # No more packets to receive
            break
        try:
            #Timeout value will be parameterized!
            log_debug("ready to recieve, timeout in: {}".format(RECV_TIMEOUT/100))
            timestamp,dev,pkt = net.recv_packet(timeout=RECV_TIMEOUT/100)
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        sw.check_timeouts(net, my_intf[0])

        if gotpkt:
            log_debug("I got a packet")
            sw.handle_ack(extract_sequence_num(pkt[3]))
            num_acks = num_acks + 1
            log_debug("just received ACK for seq_num" + str(extract_sequence_num(pkt[3])))

            # Check to see if we have completed all packets
            if sw.is_empty() and NEXT_SEND_SEQ > NUM_PKTS:
                break
        else:
            log_debug("Didn't receive anything")

            '''
            Creating the headers for the packet
            '''
            pkt = Ethernet(src=BLASTER_ETHADDR,
                           dst=BLASTEE_ETHADDR,
                           ethertype=EtherType.IPv4) + \
                  IPv4() + \
                  UDP()
            pkt[1].protocol = IPProtocol.UDP

            log_debug("creating packet: {}".format(pkt))

            syn_data = create_raw_packet_header('SYN', NEXT_SEND_SEQ)
            pkt = pkt + syn_data
            log_debug("created packet: {}".format(pkt))
            '''
            Do other things here and send packet
            '''
            if sw.handle_send(net, my_intf[0], NEXT_SEND_SEQ, pkt):
                NEXT_SEND_SEQ = NEXT_SEND_SEQ + 1


    print_output(time.time() - START_TIME, NUM_RETX, NUM_COARSE_TO, THROUGH_PUT, GOOD_PUT)
    net.shutdown()