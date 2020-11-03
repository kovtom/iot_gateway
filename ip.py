import formatting as f
from network_const import *

DUMMY_HEADER = b'\x00' * 20
DUMMY_IP_PACKET = b'\x00' * 512
MAX_IP_PACKET_LENGTH = 1500

class Header:
  '''
  IP header tipus
  '''
  def __init__(self, _header=DUMMY_HEADER):
    if isinstance(_header, bytes) and len(_header) == 20:
      self.__init(_header)
    else:
      self.error()

  
  def __init(self, _header):
    self.__len = len(_header)
    self.__version = _header[0] >> 4
    self.__header_length = (_header[0] & 0x0F) * 4
    self.__TOS = _header[1]
    self.__total_length = int.from_bytes(_header[2:4], byteorder='big')
    self.__id = int.from_bytes(_header[4:6], byteorder='big')
    self.__flags = _header[6] >> 5
    self.__fragment_offset = int.from_bytes(_header[6:8], byteorder='big') & 0x1FFF
    self.__ttl = _header[8]
    self.__proto = _header[9]
    self.__checksum = int.from_bytes(_header[10:12], byteorder='big')
    self.__src_ip_addr = _header[12:16]
    self.__dst_ip_addr = _header[16:20]
  
  def error(self):
    raise TypeError('A megadott ertek nem <bytes> tipus vagy nem megfelelo hosszusagu.')


  @property
  def header(self):
    return ((self.__version << 4) + self.__header_length // 4).to_bytes(1, byteorder='big') + \
           self.__TOS.to_bytes(1, byteorder='big') + \
           self.__total_length.to_bytes(2, byteorder='big') + \
           self.__id.to_bytes(2, byteorder='big') + \
           ((self.__flags << 13) + self.__fragment_offset).to_bytes(2, byteorder='big') + \
           self.__ttl.to_bytes(1, byteorder='big') + \
           self.__proto.to_bytes(1, byteorder='big') + \
           self.__checksum.to_bytes(2, byteorder='big') + \
           self.__src_ip_addr + self.__dst_ip_addr

  @header.setter
  def header(self, _header):
    self.__init(_header)


  @property
  def version(self):
    return self.__version

  @version.setter
  def version(self, _version):
    self.__version = _version
  

  @property
  def header_length(self):
    return self.__header_length

  @header_length.setter
  def header_length(self, _header_length):
    self.__header_length = _header_length

  
  @property
  def TOS(self):
    return self.__TOS

  @TOS.setter
  def TOS(self, _TOS):
    self.__TOS = _TOS
  

  @property
  def total_length(self):
    return self.__total_length

  @total_length.setter
  def total_length(self, _total_length):
    self.__total_length = _total_length


  @property
  def id(self):
    return self.__id

  @id.setter
  def id(self, _id):
    self.__id = _id


  @property
  def flags(self):
    return self.__flags

  @flags.setter
  def flags(self, _flags):
    self.__flags = _flags


  @property
  def fragment_offset(self):
    return self.__fragment_offset

  @fragment_offset.setter
  def fragment_offset(self, _fragment_offset):
    self.__fragment_offset = _fragment_offset


  @property
  def ttl(self):
    return self.__ttl

  @ttl.setter
  def ttl(self, _ttl):
    self.__ttl = _ttl


  @property
  def proto(self):
    return self.__proto

  @proto.setter
  def proto(self, _proto):
    self.__proto = _proto


  @property
  def checksum(self):
    return self.__checksum

  @checksum.setter
  def checksum(self, _checksum):
    self.__checksum = _checksum

  
  @property
  def src_ip_addr(self):
    return self.__src_ip_addr

  @src_ip_addr.setter
  def src_ip_addr(self, _src_ip_addr):
    self.__src_ip_addr = _src_ip_addr


  @property
  def dst_ip_addr(self):
    return self.__dst_ip_addr

  @dst_ip_addr.setter
  def dst_ip_addr(self, _dst_ip_addr):
    self.__dst_ip_addr = _dst_ip_addr



class IP:
  '''
  IP tipus
  '''
  def __init__(self, _ip_packet=DUMMY_IP_PACKET):
    if isinstance(_ip_packet, bytes) and len(_ip_packet) <= MAX_IP_PACKET_LENGTH:
      self.__init(_ip_packet)
    else:
      self.error()

  
  def __init(self, _ip_packet):
    self.__len = len(_ip_packet)
    header_length = (_ip_packet[0] & 0x0f) * 4
    self.__header = Header(_ip_packet[:header_length])
    self.__data = _ip_packet[header_length:]


  @property
  def ip_packet(self):
    return self.__header.header + self.__data

  @ip_packet.setter
  def ip_packet(self, _ip_packet):
    self.__init(_ip_packet)


  @property
  def header(self):
    return self.__header.header

  @header.setter
  def header(self, _header):
    self.__header.header = _header


  @property
  def data(self):
    return self.__data

  @data.setter
  def data(self, _data):
    if isinstance(_data, bytes):
      self.__data = _data
    else:
      self.error()


  @property
  def version(self):
    return self.__header.version

  @version.setter
  def version(self, _version):
    self.__header.version = _version


  @property
  def header_length(self):
    return self.__header.header_length

  @header_length.setter
  def header_length(self, _header_length):
    self.__header.header_length = _header_length


  @property
  def TOS(self):
    return self.__header.TOS

  @TOS.setter
  def TOS(self, _TOS):
    self.__header.TOS = _TOS


  @property
  def total_length(self):
    return self.__header.total_length

  @total_length.setter
  def total_length(self, _total_length):
    self.__header.total_length = _total_length


  @property
  def id(self):
    return self.__header.id

  @id.setter
  def id(self, _id):
    self.__header.id = _id


  @property
  def flags(self):
    return self.__header.flags

  @flags.setter
  def flags(self,_flags):
    self.__header.flags = _flags

  
  @property
  def fragment_offset(self):
    return self.__header.fragment_offset

  @fragment_offset.setter
  def fragment_offset(self, _fragment_offset):
    self.__header.fragment_offset = _fragment_offset


  @property
  def ttl(self):
    return self.__header.ttl

  @ttl.setter
  def ttl(self, _ttl):
    self.__header.ttl = _ttl


  @property
  def proto(self):
    return self.__header.proto

  @proto.setter
  def proto(self, _proto):
    self.__header.proto = _proto


  @property
  def checksum(self):
    return self.__header.checksum

  @checksum.setter
  def checksum(self, _checksum):
    self.__header.checksum = _checksum


  @property
  def src_ip_addr(self):
    return self.__header.src_ip_addr

  @src_ip_addr.setter
  def src_ip_addr(self, _src_ip_addr):
    self.__header.src_ip_addr = _src_ip_addr


  @property
  def dst_ip_addr(self):
    return self.__header.dst_ip_addr

  @dst_ip_addr.setter
  def dst_ip_addr(self, _dst_ip_addr):
    self.__header.dst_ip_addr = _dst_ip_addr


  def error(self):
    raise TypeError('A megadott parameter nem <bytes> tipus vagy nem megfelelo hosszusagu.')

