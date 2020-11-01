ETHER_TYPE = {
  '0806' : 'ARP',
  '0800' : 'IPv4',
  '8100' : 'VLAN-tagged',
  '86dd' : 'IPv6',
  '88bf' : 'Mikrotik RoMON'
}

HARD_TYPE = {
  '0001' : 'Ethernet',
  '0006' : 'IEEE_802_network',
  '0007' : 'ARCNET',
  '000F' : 'Frame_relay',
  '0010' : 'ATM',
  '0011' : 'HDLC',
  '0012' : 'Fibre_channel',
  '0013' : 'ATM2',
  '0014' : 'Serial_line'
}

PROT_TYPE = {
  '0806' : 'ARP',
  '0800' : 'IPv4',
  '8100' : 'VLAN-tagged',
  '86dd' : 'IPv6',
  '88bf' : 'Mikrotik RoMON'
}

OP = {
  '0001' : 'ARP_request',
  '0002' : 'ARP_reply',
  '0003' : 'RARP_request',
  '0004' : 'RARP_reply',
  '0005' : 'DRARP_request',
  '0006' : 'DRARP_reply',
  '0007' : 'DRARP_error',
  '0008' : 'InARP_request',
  '0009' : 'InARP_reply'
}

SELF_MAC = b'\xaa\xbb\xcc\xdd\xee\xff'

def mac(mac_type):
  return mac_type[:2].hex()+'.'+mac_type[2:4].hex()+'.'+mac_type[4:].hex()

def ip(ip_type):
  return str(int(ip_type[:1].hex(), 16))+'.'+str(int(ip_type[1:2].hex(), 16))+'.'+str(int(ip_type[2:3].hex(), 16))+'.'+str(int(ip_type[3:].hex(), 16))
