from network_const import *
#import network_const as n

def test_get_OP_code():
  assert get_key_code(OP, 'ARP_request') == b'\x00\x01'
  assert get_key_code(OP, 'ARP_reply') == b'\x00\x02'
  assert get_key_code(PROT_TYPE, 'Mikrotik RoMON') == b'\x88\xbf'
  assert get_key_code(OP, '') is None
  assert get_key_code(OP, 'err') is None

