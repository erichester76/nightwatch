#!/usr/bin/env python3
from __future__ import print_function
from scapy.all import *
import time

__version__ = "0.0.1"

def handle_arp_packet(packet):

    # Match ARP requests
    if packet[ARP].op == 1:
        print(packet[Ether].src, "looking for", packet[ARP].psrc)

    # Match ARP replies
    if packet[ARP].op == 2:
        print(packet[Ether].src, "says I am", packet[ARP].psrc)

    return

if __name__ == "__main__":
    sniff(filter="arp", prn=handle_arp_packet)
