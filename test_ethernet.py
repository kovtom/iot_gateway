import ethernet
import arp
import formatting as f

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
  
def test_Ether_frame_init():
  raw_frame = b'"3DUfw\x00\x11"3DU\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x00\x11"3DU\n\x14\x01\x01\x00\x00\x00\x00\x00\x00\n\x14\x01\x02'
  eth = ethernet.Ether_frame(raw_frame)
  assert eth.get_frame_all() == raw_frame

def test_Ether_frame_dst_mac():
  raw_frame = b'"3DUfw\x00\x11"3DU\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x00\x11"3DU\n\x14\x01\x01\x00\x00\x00\x00\x00\x00\n\x14\x01\x02'
  eth = ethernet.Ether_frame(raw_frame)
  assert eth.get_element('dst_mac') == b'"3DUfw'
  #assert eth.get_mac_f('dst_mac') == '2233.4455.6677'
  assert f.mac(eth.get_element('dst_mac')) == '2233.4455.6677'

def test_Ether_frame_src_mac():
  raw_frame = b'"3DUfw\x00\x11"3DU\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x00\x11"3DU\n\x14\x01\x01\x00\x00\x00\x00\x00\x00\n\x14\x01\x02'
  eth = ethernet.Ether_frame(raw_frame)
  assert eth.get_element('src_mac') == b'\x00\x11"3DU'

def test_Ether_frame_eth_type():
  raw_frame = b'"3DUfw\x00\x11"3DU\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x00\x11"3DU\n\x14\x01\x01\x00\x00\x00\x00\x00\x00\n\x14\x01\x02'
  eth = ethernet.Ether_frame(raw_frame)
  assert eth.get_element('type').hex() == '0806'
  #assert eth.get_type_f('0806') == 'ARP'
  assert f.ETHER_TYPE['0806'] == 'ARP'

def test_Ether_frame_eth_data():
  raw_frame = b'"3DUfw\x00\x11"3DU\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x00\x11"3DU\n\x14\x01\x01\x00\x00\x00\x00\x00\x00\n\x14\x01\x02'
  eth = ethernet.Ether_frame(raw_frame)
  assert eth.get_element('data') == b'\x00\x01\x08\x00\x06\x04\x00\x01\x00\x11"3DU\n\x14\x01\x01\x00\x00\x00\x00\x00\x00\n\x14\x01\x02'

#rawpacket.hex() -> 223344556677 001122334455 0806 00010800060400010011223344550a1401010000000000000a140102

def test_Ether_frame_set_element_dst_mac():
  raw_frame = b'"3DUfw\x00\x11"3DU\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x00\x11"3DU\n\x14\x01\x01\x00\x00\x00\x00\x00\x00\n\x14\x01\x02'
  eth = ethernet.Ether_frame(raw_frame)
  assert not eth.set_element('dst_mac', 2)
  assert eth.set_element('dst_mac', b'\xaa\xbb\xcc\xdd\xee\xff')
  assert eth.get_frame_all().hex() == 'aabbccddeeff001122334455080600010800060400010011223344550a1401010000000000000a140102'
  assert not eth.set_element('dst_mac', b'\xbb\xcc\xdd\xee\xff')

def test_Ether_frame_set_element_src_mac():
  raw_frame = b'"3DUfw\x00\x11"3DU\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x00\x11"3DU\n\x14\x01\x01\x00\x00\x00\x00\x00\x00\n\x14\x01\x02'
  eth = ethernet.Ether_frame(raw_frame)
  assert not eth.set_element('src_mac', 2)
  assert eth.set_element('src_mac', b'\xaa\xbb\xcc\xdd\xee\xff')
  assert eth.get_frame_all().hex() == '223344556677aabbccddeeff080600010800060400010011223344550a1401010000000000000a140102'
  assert not eth.set_element('src_mac', b'\xbb\xcc\xdd\xee\xff')

def test_Ether_frame_set_element_eth_type():
  raw_frame = b'"3DUfw\x00\x11"3DU\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x00\x11"3DU\n\x14\x01\x01\x00\x00\x00\x00\x00\x00\n\x14\x01\x02'
  eth = ethernet.Ether_frame(raw_frame)
  assert not eth.set_element('type', 2)
  assert eth.set_element('type', b'\x08\x00')
  assert eth.get_frame_all().hex() == '223344556677001122334455080000010800060400010011223344550a1401010000000000000a140102'
  assert not eth.set_element('type', b'\xbb')

def test_Ether_frame_set_element_eth_data():
  raw_frame = b'"3DUfw\x00\x11"3DU\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x00\x11"3DU\n\x14\x01\x01\x00\x00\x00\x00\x00\x00\n\x14\x01\x02'
  eth = ethernet.Ether_frame(raw_frame)
  assert not eth.set_element('data', 2)
  assert eth.set_element('data', b'\xff\xff\xaa\xaa\xbb\xbb')
  assert eth.get_frame_all().hex() == '2233445566770011223344550806ffffaaaabbbb'
  assert not eth.set_element('data', b'')
