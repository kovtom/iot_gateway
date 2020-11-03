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
    eth_frame = eth.Ethernet_Frame(raw_packet)
    print(str(eth_frame))
    
    if f.ETHER_TYPE[eth_frame.eth_type.hex()] == 'ARP':
      arp_packet = arp.ARP_packet(eth_frame.data)
      print(str(arp_packet))

      if f.OP[arp_packet.op.hex()] == 'ARP_request':
        if arp_packet.conv_reply_packet():
          eth_frame.src_mac_addr = arp_packet.sender_mac_addr
          eth_frame.dst_mac_addr = arp_packet.target_mac_addr
          eth_frame.data = arp_packet.packet
          print(str(arp_packet))
        
        tap.write(eth_frame.frame)

      
    packetnumber += 1


except KeyboardInterrupt:
  tap.close()
#    tun.close()
  print('\nExit')
  sys.exit(SUCCESS)
