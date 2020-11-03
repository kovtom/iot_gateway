import ethernet
import ip

def test_Header_init():
  raw_header = b'\x45\x00\x00\x54\x1c\xff\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'
  ip_header = ip.Header(raw_header)
  assert ip_header.header == raw_header

def test_Header_version_header_length():
  raw_header = b'\x45\x00\x00\x54\x1c\xff\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'
  ip_header = ip.Header(raw_header)
  ip_header.version = 5
  ip_header.header_length = 24
  assert ip_header.version == 5
  assert ip_header.header_length == 24 
  assert ip_header.header == b'\x56\x00\x00\x54\x1c\xff\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02' 

def test_Header_TOS():
  raw_header = b'\x45\x00\x00\x54\x1c\xff\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'
  ip_header = ip.Header(raw_header)
  ip_header.TOS = 0x11
  assert ip_header.TOS == 0x11 
  assert ip_header.header == b'\x45\x11\x00\x54\x1c\xff\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'

def test_Header_total_length():
  raw_header = b'\x45\x00\x00\x54\x1c\xff\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'
  ip_header = ip.Header(raw_header)
  ip_header.total_length = 0x3456
  assert ip_header.total_length == 0x3456 
  assert ip_header.header == b'\x45\x00\x34\x56\x1c\xff\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'

def test_Header_id():
  raw_header = b'\x45\x00\x00\x54\x1c\xff\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'
  ip_header = ip.Header(raw_header)
  ip_header.id = 0x1111
  assert ip_header.id == 0x1111 
  assert ip_header.header == b'\x45\x00\x00\x54\x11\x11\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'

def test_Header_flags_fragment_offset():
  raw_header = b'\x45\x00\x00\x54\x1c\xff\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'
  ip_header = ip.Header(raw_header)
  ip_header.flags = 2
  ip_header.fragment_offset = 0x1602
  assert ip_header.flags == 2
  assert ip_header.fragment_offset == 0x1602
  assert ip_header.header == b'\x45\x00\x00\x54\x1c\xff\x56\x02\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'

def test_Header_ttl():
  raw_header = b'\x45\x00\x00\x54\x1c\xff\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'
  ip_header = ip.Header(raw_header)
  ip_header.ttl = 128
  assert ip_header.ttl == 128 
  assert ip_header.header == b'\x45\x00\x00\x54\x1c\xff\x40\x00\x80\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'

def test_Header_proto():
  raw_header = b'\x45\x00\x00\x54\x1c\xff\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'
  ip_header = ip.Header(raw_header)
  ip_header.proto = 0x98
  assert ip_header.proto == 0x98 
  assert ip_header.header == b'\x45\x00\x00\x54\x1c\xff\x40\x00\x40\x98\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'

def test_Header_checksum():
  raw_header = b'\x45\x00\x00\x54\x1c\xff\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'
  ip_header = ip.Header(raw_header)
  ip_header.checksum = 0x4576
  assert ip_header.checksum == 0x4576 
  assert ip_header.header == b'\x45\x00\x00\x54\x1c\xff\x40\x00\x40\x01\x45\x76\x0a\x14\x01\x01\x0a\x14\x01\x02'

def test_Header_src_ip_addr():
  raw_header = b'\x45\x00\x00\x54\x1c\xff\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'
  ip_header = ip.Header(raw_header)
  ip_header.src_ip_addr = b'\x23\x24\x25\x26'
  assert ip_header.src_ip_addr == b'\x23\x24\x25\x26'
  assert ip_header.header == b'\x45\x00\x00\x54\x1c\xff\x40\x00\x40\x01\x07\x80\x23\x24\x25\x26\x0a\x14\x01\x02'

def test_Header_dst_ip_addr():
  raw_header = b'\x45\x00\x00\x54\x1c\xff\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'
  ip_header = ip.Header(raw_header)
  ip_header.dst_ip_addr = b'\x23\x24\x25\x26'
  assert ip_header.dst_ip_addr == b'\x23\x24\x25\x26'
  assert ip_header.header == b'\x45\x00\x00\x54\x1c\xff\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x23\x24\x25\x26'

  '''
  IP_packet test
  '''

def test_IP_version_header_length():
  raw_ip_packet = b'\x45\x00\x00\x54\x1c\xff\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02\xaa\xbb'
  ip_packet = ip.IP(raw_ip_packet)
  ip_packet.version = 5
  ip_packet.header_length = 24
  assert ip_packet.version == 5
  assert ip_packet.header_length == 24 
  assert ip_packet.header == b'\x56\x00\x00\x54\x1c\xff\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02\xaa\xbb' 

'''
def test_Header_TOS():
  raw_header = b'\x45\x00\x00\x54\x1c\xff\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'
  ip_header = ip.Header(raw_header)
  ip_header.TOS = 0x11
  assert ip_header.TOS == 0x11 
  assert ip_header.header == b'\x45\x11\x00\x54\x1c\xff\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'

def test_Header_total_length():
  raw_header = b'\x45\x00\x00\x54\x1c\xff\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'
  ip_header = ip.Header(raw_header)
  ip_header.total_length = 0x3456
  assert ip_header.total_length == 0x3456 
  assert ip_header.header == b'\x45\x00\x34\x56\x1c\xff\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'

def test_Header_id():
  raw_header = b'\x45\x00\x00\x54\x1c\xff\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'
  ip_header = ip.Header(raw_header)
  ip_header.id = 0x1111
  assert ip_header.id == 0x1111 
  assert ip_header.header == b'\x45\x00\x00\x54\x11\x11\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'

def test_Header_flags_fragment_offset():
  raw_header = b'\x45\x00\x00\x54\x1c\xff\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'
  ip_header = ip.Header(raw_header)
  ip_header.flags = 2
  ip_header.fragment_offset = 0x1602
  assert ip_header.flags == 2
  assert ip_header.fragment_offset == 0x1602
  assert ip_header.header == b'\x45\x00\x00\x54\x1c\xff\x56\x02\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'

def test_Header_ttl():
  raw_header = b'\x45\x00\x00\x54\x1c\xff\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'
  ip_header = ip.Header(raw_header)
  ip_header.ttl = 128
  assert ip_header.ttl == 128 
  assert ip_header.header == b'\x45\x00\x00\x54\x1c\xff\x40\x00\x80\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'

def test_Header_proto():
  raw_header = b'\x45\x00\x00\x54\x1c\xff\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'
  ip_header = ip.Header(raw_header)
  ip_header.proto = 0x98
  assert ip_header.proto == 0x98 
  assert ip_header.header == b'\x45\x00\x00\x54\x1c\xff\x40\x00\x40\x98\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'

def test_Header_checksum():
  raw_header = b'\x45\x00\x00\x54\x1c\xff\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'
  ip_header = ip.Header(raw_header)
  ip_header.checksum = 0x4576
  assert ip_header.checksum == 0x4576 
  assert ip_header.header == b'\x45\x00\x00\x54\x1c\xff\x40\x00\x40\x01\x45\x76\x0a\x14\x01\x01\x0a\x14\x01\x02'

def test_Header_src_ip_addr():
  raw_header = b'\x45\x00\x00\x54\x1c\xff\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'
  ip_header = ip.Header(raw_header)
  ip_header.src_ip_addr = b'\x23\x24\x25\x26'
  assert ip_header.src_ip_addr == b'\x23\x24\x25\x26'
  assert ip_header.header == b'\x45\x00\x00\x54\x1c\xff\x40\x00\x40\x01\x07\x80\x23\x24\x25\x26\x0a\x14\x01\x02'

def test_Header_dst_ip_addr():
  raw_header = b'\x45\x00\x00\x54\x1c\xff\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'
  ip_header = ip.Header(raw_header)
  ip_header.dst_ip_addr = b'\x23\x24\x25\x26'
  assert ip_header.dst_ip_addr == b'\x23\x24\x25\x26'
  assert ip_header.header == b'\x45\x00\x00\x54\x1c\xff\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x23\x24\x25\x26'
'''