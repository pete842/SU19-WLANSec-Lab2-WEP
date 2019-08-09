#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

__author__ = "Abraham Rubinstein"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "abraham.rubinstein@heig-vd.ch"
__status__ = "Prototype"

from scapy.all import *
import binascii
import rc4

# wep key AA:AA:AA:AA:AA
key = '\xaa\xaa\xaa\xaa\xaa'

# We read the original encrypted message from the wireshark file - rdpcap always returns an array, even if the pcap only contains one frame
arp = rdpcap('arp.cap')[0]
# The rc4 seed is composed by the IV+key
seed = arp.iv + key

data = raw_input("Please enter a message of length below 37 bytes:\n").ljust(36, '\0')[:36]

icv = crc32(data) & 0xffffffff

icv_enc = struct.pack('<L', icv)

message = data + icv_enc

message_enc = rc4.rc4crypt(message, seed)

icv_enc = message_enc[-4:]
icv_numerique, = struct.unpack('!L', icv_enc)

text_encrypted = message_enc[:-4]

arp.wepdata = text_encrypted
arp.icv = icv_numerique
print icv_numerique
wrpcap('arp_custom.cap', arp)
