import network_const as n
import formatting as f

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
  
  @property
  def dst_mac_addr(self):
    return self.__dst_mac_addr

  @dst_mac_addr.setter
  def dst_mac_addr(self, _dst_mac_addr):
    if isinstance(_dst_mac_addr, bytes) and len(_dst_mac_addr) == 6:
      self.__dst_mac_addr = _dst_mac_addr
      #return True

    else:
      self.error()
  
  @property
  def src_mac_addr(self):
    return self.__src_mac_addr

  @src_mac_addr.setter
  def src_mac_addr(self, _src_mac_addr):

    if isinstance(_src_mac_addr, bytes) and len(_src_mac_addr) == 6:
      self.__src_mac_addr = _src_mac_addr

    else:
      self.error()

  @property
  def eth_type(self):
    return self.__eth_type

  @eth_type.setter
  def eth_type(self, _eth_type):

    if isinstance(_eth_type, bytes) and len(_eth_type) == 2:
      self.__eth_type = _eth_type

    else:
      self.error()

  @property
  def header(self):
    return self.__dst_mac_addr + self.__src_mac_addr + self.__eth_type 


  def error(self):
    raise TypeError("A megadott ertek nem 'bytes' tipus, vagy nem megfelelo hosszusagu")


class Ethernet_Frame:
  '''
  Ethernet keret tipus
  '''
  def __init__(self, _eth_frame=TEMP_HEADER+TEMP_DATA):
    self.__mac_header = MAC_Header()
    self.__data = bytes()

    if isinstance(_eth_frame, bytes) and len(_eth_frame) >= MIN_ETH_FRAME_LEN:
      self.__mac_header = MAC_Header(_eth_frame[:14])
      self.__data = _eth_frame[14:]


    else:
      self.error()
  
  @property
  def data(self):
    return self.__data

  @data.setter
  def data(self, _data):

    if isinstance(_data, bytes) and len(_data) >= 28:
      self.__data = _data

    else:
      self.error()
  
  @property
  def frame(self):
    return self.__mac_header.header + self.__data
    

  @property
  def header(self):
    return self.__mac_header.header

  @header.setter
  def header(self, _mac_header):

    if isinstance(_mac_header, bytes) and len(_mac_header) == 14:
      self.__mac_header = MAC_Header(_mac_header)

    else:
      self.error()


  @property
  def dst_mac_addr(self):
    return self.__mac_header.dst_mac_addr
  
  @dst_mac_addr.setter
  def dst_mac_addr(self, _dst_mac_addr):
    self.__mac_header.dst_mac_addr = _dst_mac_addr


  @property
  def src_mac_addr(self):
    return self.__mac_header.src_mac_addr
  
  @src_mac_addr.setter
  def src_mac_addr(self, _src_mac_addr):
    self.__mac_header.src_mac_addr = _src_mac_addr


  @property
  def eth_type(self):
    return self.__mac_header.eth_type

  @eth_type.setter
  def eth_type(self, _eth_type):
    self.__mac_header.eth_type = _eth_type


  def error(self):
    raise TypeError("A megadott ertek nem 'bytes' tipus, vagy nem megfelelo hosszusagu")

  
  def __repr__(self):
    name = __name__
    smac = f.mac(self.src_mac_addr)
    dmac = f.mac(self.dst_mac_addr)
    etype = n.ETHER_TYPE[self.eth_type.hex()]
    return ('%s: <smac: %s dmac: %s etype: %s>'
            % (name, smac, dmac, etype))
