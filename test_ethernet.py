'''
---------------------------------------
Packet number: 51
__init__ EthernetFrame ethernet
rawpacket -> b'"3DUfw \x00\x11"3DU \x08\x06 \x00\x01\x08\x00\x06\x04\x00\x01\x00\x11"3DU\n\x14\x01\x01\x00\x00\x00\x00\x00\x00\n\x14\x01\x02'
rawpacket.hex() -> 223344556677 001122334455 0806 00010800060400010011223344550a1401010000000000000a140102
dstmac -> 223344556677
srcmac ->  001122334455
ethertype -> 0x806
ethertype_str -> ARP
data -> 00010800060400010011223344550a1401010000000000000a140102
DEBUG:  __init__ ARP_packet arp
hardtype -> 0x1 ethernet <class 'int'>
prottype -> 0x800 ip_datagram <class 'int'>
hardsize -> 6 <class 'int'>
protsize -> 4 <class 'int'>
op -> 0x1 arp_request <class 'int'>
sender_eth_addr -> 0:11:22:33:44:55 <class 'bytes'>
sender_ip_addr -> 10.20.1.1 <class 'bytes'>
target_eth_addr -> 0:0:0:0:0:0 <class 'bytes'>
target_ip_addr -> 10.20.1.2 <class 'bytes'>
Debug end
DEBUG:  __init__ ARP_packet arp
hardtype -> 0x1 ethernet <class 'int'>
prottype -> 0x800 ip_datagram <class 'int'>
hardsize -> 6 <class 'int'>
protsize -> 4 <class 'int'>
op -> 0x2 arp_reply <class 'int'>
sender_eth_addr -> 22:33:44:55:66:77 <class 'bytes'>
sender_ip_addr -> 10.20.1.2 <class 'bytes'>
target_eth_addr -> 0:11:22:33:44:55 <class 'bytes'>
target_ip_addr -> 10.20.1.1 <class 'bytes'>
Debug end
__init__ EthernetFrame ethernet
rawpacket -> b'\x00\x01\x08\x00\x06\x04\x00\x02"3DUfw\n\x14\x01\x02\x00\x11"3DU\n\x14\x01\x01'
rawpacket.hex() -> 00010800060400022233445566770a1401020011223344550a140101
dstmac -> 001122334455
srcmac ->  223344556677
ethertype -> 0x806
ethertype_str -> ARP
data -> 00010800060400022233445566770a1401020011223344550a140101
***************************************
'''

import ethernet as e

ETH_RAW_FRAME = b'"3DUfw\x00\x11"3DU\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x00\x11"3DU\n\x14\x01\x01\x00\x00\x00\x00\x00\x00\n\x14\x01\x02'
ETH_RAW_HEADER = b'"3DUfw\x00\x11"3DU\x08\x06'
ETH_OTHER_RAW_HEADER = b'\xaa\xbb\xcc\xdd\xee\xff\x00\x11"3DU\x08\x06'
ETH_OTHER_DATA = b'x00\x01\x08\x00\x06\x04\x00\x01\x00\x11"3DU\n\x14\x01\x02\x00\x00\x00\x00\x00\x00\n\x14\x01\x02'
'''
MAC_Header test
'''
def test_MAC_Header__get_header():
  mac_header = e.MAC_Header(ETH_RAW_HEADER)
  assert mac_header.header == ETH_RAW_HEADER

def test_MAC_Header__dst_mac_addr():
  mac_header = e.MAC_Header(ETH_RAW_HEADER)
  assert mac_header.dst_mac_addr == b'"3DUfw'
  mac_header.dst_mac_addr = b'\xaa\xbb\xcc\xdd\xee\xff'
  assert mac_header.dst_mac_addr == b'\xaa\xbb\xcc\xdd\xee\xff'

def test_MAC_Header__src_mac_addr():
  mac_header = e.MAC_Header(ETH_RAW_HEADER)
  assert mac_header.src_mac_addr == b'\x00\x11"3DU'
  mac_header.src_mac_addr = b'\xaa\xbb\xcc\xdd\xee\xff'
  assert mac_header.src_mac_addr == b'\xaa\xbb\xcc\xdd\xee\xff'

def test_MAC_Header__eth_type():
  mac_header = e.MAC_Header(ETH_RAW_HEADER)
  assert mac_header.eth_type == b'\x08\x06'
  mac_header.eth_type = b'\xaa\xbb'
  assert mac_header.eth_type == b'\xaa\xbb'

'''
Ethernet_Frame test
'''
def test_Ethernet_Frame__get_mac_header():
  eth_frame = e.Ethernet_Frame(ETH_RAW_FRAME)
  assert eth_frame.header == b'"3DUfw\x00\x11"3DU\x08\x06'

def test_Ethernet_Frame__get_data():
  eth_frame = e.Ethernet_Frame(ETH_RAW_FRAME)
  assert eth_frame.data == b'\x00\x01\x08\x00\x06\x04\x00\x01\x00\x11"3DU\n\x14\x01\x01\x00\x00\x00\x00\x00\x00\n\x14\x01\x02'

def test_Ethernet_Frame__set_header():
  eth_frame = e.Ethernet_Frame(ETH_RAW_FRAME)
  eth_frame.header = ETH_OTHER_RAW_HEADER
  assert eth_frame.header == ETH_OTHER_RAW_HEADER

def test_Ethernet_Frame__set_data():
  eth_frame = e.Ethernet_Frame(ETH_RAW_FRAME)
  eth_frame.data = ETH_OTHER_DATA
  assert eth_frame.data == ETH_OTHER_DATA

def test_Ethernet_Frame__get_frame():
  eth_frame = e.Ethernet_Frame(ETH_RAW_FRAME)
  assert eth_frame.frame == ETH_RAW_FRAME

# b'"3DUfw \x00\x11"3DU \x08\x06 \x00\x01\x08\x00\x06\x04\x00\x01\x00\x11"3DU\n\x14\x01\x01\x00\x00\x00\x00\x00\x00\n\x14\x01\x02'

def test_Ethernet_Frame__dst_mac_addr():
  eth_frame = e.Ethernet_Frame(ETH_RAW_FRAME)
  assert eth_frame.dst_mac_addr == b'"3DUfw'

def test_Ethernet_Frame__src_mac_addr():
  eth_frame = e.Ethernet_Frame(ETH_RAW_FRAME)
  assert eth_frame.src_mac_addr == b'\x00\x11"3DU'

def test_Ethernet_Frame__eth_type():
  eth_frame = e.Ethernet_Frame(ETH_RAW_FRAME)
  assert eth_frame.eth_type == b'\x08\x06'



