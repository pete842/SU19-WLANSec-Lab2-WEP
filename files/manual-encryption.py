#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
# Team: Pierre Kohler, Pierrick Müller, Kim Wonkyeong
""" Manually encrypt a wep message given the WEP key"""

from scapy.all import *
import binascii
import rc4

# wep key AA:AA:AA:AA:AA
key = '\xaa\xaa\xaa\xaa\xaa'

# We read the original encrypted message from the wireshark file - rdpcap always returns an array, even if the pcap only contains one frame
arp = rdpcap('arp.cap')[0]
# The rc4 seed is composed by the IV+key
seed = arp.iv + key

# Take the data to send from the user input
data = raw_input("Please enter a message of length below 37 bytes:\n").ljust(36, '\0')[:36]

# Define the icv by computing the crc32 of the data and keeping only the last 4 bytes 
icv = crc32(data) & 0xffffffff

# Encrypt the icv as little-endian long
icv_enc = struct.pack('<L', icv)

# Construct the message (cleartext)
message = data + icv_enc

# Encrypt this message with rc4 with the seed being iv|wepkey
message_enc = rc4.rc4crypt(message, seed)

# Get the encrypted icv from the (encrypted) message
icv_enc = message_enc[-4:]
# Unpack it as big-endian long
icv_numerique, = struct.unpack('!L', icv_enc)

# Get the encrypted data from the (encrypted) message
text_encrypted = message_enc[:-4]

# Complete the packet
arp.wepdata = text_encrypted
arp.icv = icv_numeriqu

# Saving it in a pcap file
wrpcap('arp_custom.cap', arp)

