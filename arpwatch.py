#!/usr/bin/env python3
from __future__ import print_function
from scapy.all import *
import time

__version__ = "0.0.1"

def handle_arp_packet(packet):

    # Match ARP requests
    if packet[ARP].op == ARP.who_has:
        print('New ARP Request')
        print(packet.summary())
        #print(ls(packet))
        print(packet[Ether].src, "has IP", packet[ARP].psrc)

    # Match ARP replies
    if packet[ARP].op == ARP.is_at:
        print('New ARP Reply')
        print(packet.summary())
        #print(ls(packet))

    return

if __name__ == "__main__":
    sniff(filter="arp", iface='en1', prn=handle_arp_packet)