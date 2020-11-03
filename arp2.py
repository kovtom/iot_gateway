import formatting as f
from network_const import *

TEMP_ARP_PACKET = b'\x00' * 28

class ARP_packet:
  """
  ARP packet tipus
  """
  def __init__(self, _packet=TEMP_ARP_PACKET):
    #self.__packet = bytes()
    if isinstance(_packet, bytes):
      self.__init(_packet)
    else:
      raise TypeError('A megadott ertek nem <bytes> tipus')

  def __init(self, _packet):
    self.__packet = _packet
    self.__hard_type = self.__packet[:2]
    self.__prot_type = self.__packet[2:4]
    self.__hard_size = self.__packet[4:5]
    self.__prot_size = self.__packet[5:6]
    self.__op = self.__packet[6:8]
    self.__sender_mac_addr = self.__packet[8:14]
    self.__sender_ip_addr = self.__packet[14:18]
    self.__target_mac_addr = self.__packet[18:24]
    self.__target_ip_addr = self.__packet[24:]


  @property
  def packet(self):
    self.__packet = self.__hard_type + self.__prot_type + \
                    self.__hard_size + self.__prot_size + \
                    self.__op + \
                    self.__sender_mac_addr + self.__sender_ip_addr + \
                    self.__target_mac_addr + self.__target_ip_addr
    return self.__packet

  @packet.setter
  def packet(self, _packet):
    if isinstance(_packet, bytes) and len(_packet) == 28:
      self.__init(_packet)
    else:
      self.error()
  

  @property
  def hard_type(self):
    return self.__hard_type
  
  @hard_type.setter
  def hard_type(self, _hard_type):
    if isinstance(_hard_type, bytes) and len(_hard_type) == 2:
      self.__hard_type = _hard_type
    else:
      self.error()


  @property
  def prot_type(self):
    return self.__prot_type

  @prot_type.setter
  def prot_type(self, _prot_type):
    if isinstance(_prot_type, bytes) and len(_prot_type) == 2:
      self.__prot_type = _prot_type
    else:
      self.error()


  @property
  def hard_size(self):
    return self.__hard_size

  @hard_size.setter
  def hard_size(self, _hard_size):
    if isinstance(_hard_size, bytes) and len(_hard_size) == 1:
      self.__hard_size = _hard_size
    else:
      self.error()


  @property
  def prot_size(self):
    return self.__prot_size

  @prot_size.setter
  def prot_size(self, _prot_size):
    if isinstance(_prot_size, bytes) and len(_prot_size) == 1:
      self.__prot_size = _prot_size
    else:
      self.error()


  @property
  def op(self):
    return self.__op

  @op.setter
  def op(self, _op):
    if isinstance(_op, bytes) and len(_op) == 2:
      self.__op = _op
    else:
      self.error()


  @property
  def sender_mac_addr(self):
    return self.__sender_mac_addr

  @sender_mac_addr.setter
  def sender_mac_addr(self, _sender_mac_addr):
    if isinstance(_sender_mac_addr, bytes) and len(_sender_mac_addr) == 6:
      self.__sender_mac_addr = _sender_mac_addr
    else:
      self.error()


  @property
  def sender_ip_addr(self):
    return self.__sender_ip_addr

  @sender_ip_addr.setter
  def sender_ip_addr(self, _sender_ip_addr):
    if isinstance(_sender_ip_addr, bytes) and len(_sender_ip_addr) == 4:
      self.__sender_ip_addr = _sender_ip_addr
    else:
      self.error()

  @property
  def target_mac_addr(self):
    return self.__target_mac_addr

  @target_mac_addr.setter
  def target_mac_addr(self, _target_mac_addr):
    if isinstance(_target_mac_addr, bytes) and len(_target_mac_addr) == 6:
      self.__target_mac_addr = _target_mac_addr
    else:
      self.error()

  
  @property
  def target_ip_addr(self):
    return self.__target_ip_addr

  @target_ip_addr.setter
  def target_ip_addr(self, _target_ip_addr):
    if isinstance(_target_ip_addr, bytes) and len(_target_ip_addr) == 4:
      self.__target_ip_addr = _target_ip_addr
    else:
      self.error()

  @property  
  def reply_packet(self):
    if self.op == get_key_code(OP, 'ARP_request'):
      self.op = get_key_code(OP, 'ARP_reply')
      sender_mac_addr = self.sender_mac_addr
      sender_ip_addr = self.sender_ip_addr
      self.sender_mac_addr = f.SELF_MAC
      self.sender_ip_addr = self.target_ip_addr
      self.target_mac_addr = sender_mac_addr
      self.target_ip_addr = sender_ip_addr
      return self.packet
    return None









  def error(self):  
    raise TypeError('A megadott tipus nem <bytes> vagy nem megfelelo hosszusagu')
  



















