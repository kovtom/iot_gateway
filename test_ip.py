import ethernet
import ip

def test_Header_init():
  raw_header = b'\x45\x00\x00\x54\x1c\xff\x40\x00\x40\x01\x07\x80\x0a\x14\x01\x01\x0a\x14\x01\x02'
  ip_packet = ip.Header(raw_header)
  assert ip_packet.header == raw_header
