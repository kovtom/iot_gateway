import arp
import ethernet

def test_ARP_packet_init():
  raw_frame = b'"3DUfw\x00\x11"3DU\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x00\x11"3DU\n\x14\x01\x01\x00\x00\x00\x00\x00\x00\n\x14\x01\x02'
  eth = ethernet.Ether_frame(raw_frame)
  arp_packet = arp.ARP_packet(eth.get_element('data'))
#  assert arp_packet.packet_all.hex() == '00010800060400010011223344550a1401010000000000000a140102'
  assert arp_packet.get_packet_all().hex() == '00010800060400010011223344550a1401010000000000000a140102'
  assert arp_packet.get_element('hard_type').hex() == '0001'
  assert arp_packet.get_element('prot_type').hex() == '0800'
  assert arp_packet.get_element('hard_size').hex() == '06'
  assert arp_packet.get_element('prot_size').hex() == '04'
  assert arp_packet.get_element('op').hex() == '0001'
  assert arp_packet.get_element('sender_mac_addr').hex() == '001122334455'
  assert arp_packet.get_element('sender_ip_addr').hex() == '0a140101'
  assert arp_packet.get_element('target_mac_addr').hex() == '000000000000'
  assert arp_packet.get_element('target_ip_addr').hex() == '0a140102'

# '0001 0800 06 04 0001 001122334455 0a140101 000000000000 0a140102'
# '00010800060400010011223344550a1401010000000000000a140102'

def test_ARP_packet_set_hard_type():
  raw_frame = b'"3DUfw\x00\x11"3DU\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x00\x11"3DU\n\x14\x01\x01\x00\x00\x00\x00\x00\x00\n\x14\x01\x02'
  eth = ethernet.Ether_frame(raw_frame)
  arp_packet = arp.ARP_packet(eth.get_element('data'))
  assert not arp_packet.set_element('hard_type', 2)
  assert arp_packet.set_element('hard_type', b'\x33\x44')
  assert arp_packet.get_packet_all().hex() == '33440800060400010011223344550a1401010000000000000a140102'
  assert not arp_packet.set_element('hard_type', b'\xbb')

def test_ARP_packet_set_prot_type():
  raw_frame = b'"3DUfw\x00\x11"3DU\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x00\x11"3DU\n\x14\x01\x01\x00\x00\x00\x00\x00\x00\n\x14\x01\x02'
  eth = ethernet.Ether_frame(raw_frame)
  arp_packet = arp.ARP_packet(eth.get_element('data'))
  assert not arp_packet.set_element('prot_type', 2)
  assert arp_packet.set_element('prot_type', b'\x33\x44')
  assert arp_packet.get_packet_all().hex() == '00013344060400010011223344550a1401010000000000000a140102'
  assert not arp_packet.set_element('prot_type', b'\xbb')

def test_ARP_packet_set_hard_size():
  raw_frame = b'"3DUfw\x00\x11"3DU\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x00\x11"3DU\n\x14\x01\x01\x00\x00\x00\x00\x00\x00\n\x14\x01\x02'
  eth = ethernet.Ether_frame(raw_frame)
  arp_packet = arp.ARP_packet(eth.get_element('data'))
  assert not arp_packet.set_element('hard_size', 2)
  assert arp_packet.set_element('hard_size', b'\x07')
  assert arp_packet.get_packet_all().hex() == '00010800070400010011223344550a1401010000000000000a140102'
  assert not arp_packet.set_element('hard_size', b'\xbb\xcc')

def test_ARP_packet_set_prot_size():
  raw_frame = b'"3DUfw\x00\x11"3DU\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x00\x11"3DU\n\x14\x01\x01\x00\x00\x00\x00\x00\x00\n\x14\x01\x02'
  eth = ethernet.Ether_frame(raw_frame)
  arp_packet = arp.ARP_packet(eth.get_element('data'))
  assert not arp_packet.set_element('prot_size', 2)
  assert arp_packet.set_element('prot_size', b'\x05')
  assert arp_packet.get_packet_all().hex() == '00010800060500010011223344550a1401010000000000000a140102'
  assert not arp_packet.set_element('prot_size', b'\xbb\xcc')

def test_ARP_packet_set_op():
  raw_frame = b'"3DUfw\x00\x11"3DU\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x00\x11"3DU\n\x14\x01\x01\x00\x00\x00\x00\x00\x00\n\x14\x01\x02'
  eth = ethernet.Ether_frame(raw_frame)
  arp_packet = arp.ARP_packet(eth.get_element('data'))
  assert not arp_packet.set_element('op', 2)
  assert arp_packet.set_element('op', b'\x05\x06')
  assert arp_packet.get_packet_all().hex() == '00010800060405060011223344550a1401010000000000000a140102'
  assert not arp_packet.set_element('op', b'\xbb')

# '0001 0800 06 04 0001 001122334455 0a140101 000000000000 0a140102'

def test_ARP_packet_set_sender_mac_addr():
  raw_frame = b'"3DUfw\x00\x11"3DU\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x00\x11"3DU\n\x14\x01\x01\x00\x00\x00\x00\x00\x00\n\x14\x01\x02'
  eth = ethernet.Ether_frame(raw_frame)
  arp_packet = arp.ARP_packet(eth.get_element('data'))
  assert not arp_packet.set_element('sender_mac_addr', 2)
  assert arp_packet.set_element('sender_mac_addr', b'\x55\x66\x77\x88\x99\xaa')
  assert arp_packet.get_packet_all().hex() == '00010800060400015566778899aa0a1401010000000000000a140102'
  assert not arp_packet.set_element('sender_mac_addr', b'\xbb')

def test_ARP_packet_set_sender_ip_addr():
  raw_frame = b'"3DUfw\x00\x11"3DU\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x00\x11"3DU\n\x14\x01\x01\x00\x00\x00\x00\x00\x00\n\x14\x01\x02'
  eth = ethernet.Ether_frame(raw_frame)
  arp_packet = arp.ARP_packet(eth.get_element('data'))
  assert not arp_packet.set_element('sender_ip_addr', 2)
  assert arp_packet.set_element('sender_ip_addr', b'\x0b\x16\x01\x02')
  assert arp_packet.get_packet_all().hex() == '00010800060400010011223344550b1601020000000000000a140102'
  assert not arp_packet.set_element('sender_ip_addr', b'\xbb')

def test_ARP_packet_set_target_mac_addr():
  raw_frame = b'"3DUfw\x00\x11"3DU\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x00\x11"3DU\n\x14\x01\x01\x00\x00\x00\x00\x00\x00\n\x14\x01\x02'
  eth = ethernet.Ether_frame(raw_frame)
  arp_packet = arp.ARP_packet(eth.get_element('data'))
  assert not arp_packet.set_element('target_mac_addr', 2)
  assert arp_packet.set_element('target_mac_addr', b'\x55\x66\x77\x88\x99\xaa')
  assert arp_packet.get_packet_all().hex() == '00010800060400010011223344550a1401015566778899aa0a140102'
  assert not arp_packet.set_element('target_mac_addr', b'\xbb')

def test_ARP_packet_set_target_ip_addr():
  raw_frame = b'"3DUfw\x00\x11"3DU\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x00\x11"3DU\n\x14\x01\x01\x00\x00\x00\x00\x00\x00\n\x14\x01\x02'
  eth = ethernet.Ether_frame(raw_frame)
  arp_packet = arp.ARP_packet(eth.get_element('data'))
  assert not arp_packet.set_element('target_ip_addr', 2)
  assert arp_packet.set_element('target_ip_addr', b'\x0b\x16\x01\x02')
  assert arp_packet.get_packet_all().hex() == '00010800060400010011223344550a1401010000000000000b160102'
  assert not arp_packet.set_element('target_ip_addr', b'\xbb')

# '0001 0800 06 04 0001 001122334455 0a140101 000000000000 0a140102'

def test_ARP_packet_reply_packet():
  raw_frame = b'"3DUfw\x00\x11"3DU\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x00\x11"3DU\n\x14\x01\x01\x00\x00\x00\x00\x00\x00\n\x14\x01\x02'
  eth = ethernet.Ether_frame(raw_frame)
  arp_packet = arp.ARP_packet(eth.get_element('data'))
  assert arp_packet.reply_packet().hex() ==  '0001080006040002aabbccddeeff0a1401020011223344550a140101'

