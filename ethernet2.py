import network_const as n

'''
Konstansok
'''
ETHER_TYPE = {
  '0806' : 'ARP',
  '0800' : 'IPv4',
  '8100' : 'VLAN-tagged',
  '86dd' : 'IPv6',
  '88bf' : 'Mikrotik RoMON'
}

TEMP_HEADER = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
TEMP_DATA = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
MIN_ETH_FRAME_LEN = 6+6+2+28

class MAC_Header:
  '''
  Ethernet keret MAC header tipus
  '''
  def __init__(self, _header=TEMP_HEADER):
    self.__dst_mac_addr = bytes()
    self.__src_mac_addr = bytes()
    self.__eth_type = bytes()
    
    if isinstance(_header, bytes) and len(_header) == 14:
      self.__dst_mac_addr = _header[:6]
      self.__src_mac_addr = _header[6:12]
      self.__eth_type = _header[12:]
    
    else:
      self.error()
  

  def set_dst_mac_addr(self, _dst_mac_addr):

    if isinstance(_dst_mac_addr, bytes) and len(_dst_mac_addr) == 6:
      self.__dst_mac_addr = _dst_mac_addr
      return True

    else:
      self.error()


  def set_src_mac_addr(self, _src_mac_addr):

    if isinstance(_src_mac_addr, bytes) and len(_src_mac_addr) == 6:
      self.__src_mac_addr = _src_mac_addr
      return True

    else:
      self.error()


  def set_eth_type(self, _eth_type):

    if isinstance(_eth_type, bytes) and len(_eth_type) == 2:
      self.__eth_type = _eth_type
      return True

    else:
      self.error()


  def get_dst_mac_addr(self):
    return self.__dst_mac_addr


  def get_src_mac_addr(self):
    return self.__src_mac_addr
  

  def get_eth_type(self):
    return self.__eth_type

  
  def get_header(self):
    return self.__dst_mac_addr + self.__src_mac_addr + self.__eth_type 


  def error(self):
    raise TypeError("A megadott ertek nem 'bytes' tipus, vagy nem megfelelo hosszusagu")


class Ethernet_Frame:
  '''
  Ethernet keret tipus
  '''
  def __init__(self, _eth_frame=TEMP_HEADER+TEMP_DATA):
    self.mac_header = MAC_Header()
    self.__data = bytes()

    if isinstance(_eth_frame, bytes) and len(_eth_frame) >= MIN_ETH_FRAME_LEN:
      self.mac_header = MAC_Header(_eth_frame[:14])
      self.__data = _eth_frame[14:]

    else:
      self.error()
  

  def get_data(self):
    return self.__data


  def get_frame(self):
    return self.mac_header.get_header() + self.__data
    

  def set_mac_header(self, _mac_header):

    if isinstance(_mac_header, bytes) and len(_mac_header) == 14:
      self.mac_header = MAC_Header(_mac_header)
      return True

    else:
      self.error()


  def set_data(self, _data):

    if isinstance(_data, bytes) and len(_data) >= 28:
      self.__data = _data
      return True

    else:
      self.error()
     

  def error(self):
    raise TypeError("A megadott ertek nem 'bytes' tipus, vagy nem megfelelo hosszusagu")