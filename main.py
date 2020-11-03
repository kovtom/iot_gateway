import sys
from pytun import TunTapDevice, IFF_TAP, IFF_NO_PI # pylint: disable=no-name-in-module
import pytun
import struct
import zlib
import ethernet as eth
import formatting as f
import arp
import logging

DEVICE_NAME = 'tap72'
#DEVICE_NAME = 'tun72'
SUCCESS = 0
ERROR = -1

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)


log.debug('Start: %s , Filename: %s', __name__, __file__)

print('Create TAP device. Name = <'+DEVICE_NAME+'>')
try:
  tap = TunTapDevice(name=DEVICE_NAME, flags=IFF_TAP | IFF_NO_PI)
#    tun = TunTapDevice(name=DEVICE_NAME)
  print('Success')
except:
  print('TAP device create failure.')
  sys.exit(ERROR)

print('Setting TAP device IP addr, Netmask, MTU, MAC')
try:
#   '''
  tap.addr = '10.20.1.1'
  tap.netmask = '255.255.255.0'
  tap.mtu = 1500
  tap.hwaddr = b'\x00\x11\x22\x33\x44\x55'
  '''
  tun.addr = '10.20.1.1'
  tun.netmask = '255.255.255.0'
  tun.mtu = 1500
  #tun.dstaddr = '10.20.1.10'
  #tun.hwaddr = b'\x00\x11\x22\x33\x44\x55'
  '''
  print('Success')
except:
  print('Settings failure')
  sys.exit(ERROR)


print('TAP device UP')
try:
  tap.up()
#    tun.up()
  print('Success')
except:
  print('TAP up failure')
  sys.exit(ERROR)

packetnumber = 0

try:
  while(True):
    raw_packet = tap.read(tap.mtu)  # buf = tun.read(tun.mtu)
    #eth_frame = eth.Ether_frame(raw_packet)
    eth_frame = eth.Ethernet_Frame(raw_packet)

    print('----------Ethernet frame--------------')
    print('Packet number:', packetnumber)
    #print('src_mac -> ', f.mac(eth_frame.get_element('src_mac')))
    print('src_mac -> ', f.mac(eth_frame.src_mac_addr))
    #print('dst_mac -> ', f.mac(eth_frame.get_element('dst_mac')))
    print('dst_mac -> ', f.mac(eth_frame.dst_mac_addr))
    #print('eth type ->', f.ETHER_TYPE[eth_frame.get_element('type').hex()])
    print('eth type ->', f.ETHER_TYPE[eth_frame.eth_type.hex()])
    #print('data ->', eth_frame.get_element('data').hex())
    print('data ->', eth_frame.data.hex())
    #print('raw_data ->', eth_frame.get_frame_all().hex())
    print('ethernet_frame ->', eth_frame.frame.hex())
    print('***************************************')

    if f.ETHER_TYPE[eth_frame.eth_type.hex()] == 'ARP':
      arp_packet = arp.ARP_packet(eth_frame.data)
      print('-------------ARP packet------------------')
      print('hard_type -> ', f.HARD_TYPE[arp_packet.hard_type.hex()])
      print('prot_type -> ', f.PROT_TYPE[arp_packet.prot_type.hex()])
      print('hard_size -> ', arp_packet.hard_size.hex())
      print('prot_size -> ', arp_packet.prot_size.hex())
      print('op -> ', f.OP[arp_packet.hard_type.hex()])
      print('sender_mac_addr -> ', f.mac(arp_packet.sender_mac_addr))
      print('sender_ip_addr -> ', f.ip(arp_packet.sender_ip_addr))
      print('target_mac_addr -> ', f.mac(arp_packet.target_mac_addr))
      print('target_ip_addr -> ', f.ip(arp_packet.target_ip_addr))
      print('*****************************************')

      if f.OP[arp_packet.op.hex()] == 'ARP_request':
        if arp_packet.conv_reply_packet():
          eth_frame.src_mac_addr = arp_packet.sender_mac_addr
          eth_frame.dst_mac_addr = arp_packet.target_mac_addr
          eth_frame.data = arp_packet.packet
        
        tap.write(eth_frame.frame)

      
    packetnumber += 1


except KeyboardInterrupt:
  tap.close()
#    tun.close()
  print('\nExit')
  sys.exit(SUCCESS)
