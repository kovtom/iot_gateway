import formatting as f

class ARP_packet:
  """
  ARP packet tipus
  """
  def __init__(self, _raw_packet):
    self.__packet_all = bytes()
    self.__packet = dict()
    if isinstance(_raw_packet, bytes):
      self.__packet_all = _raw_packet
      self.__packet['hard_type'] = self.__packet_all[:2]
      self.__packet['prot_type'] = self.__packet_all[2:4]
      self.__packet['hard_size'] = self.__packet_all[4:5]
      self.__packet['prot_size'] = self.__packet_all[5:6]
      self.__packet['op'] = self.__packet_all[6:8]
      self.__packet['sender_mac_addr'] = self.__packet_all[8:14]
      self.__packet['sender_ip_addr'] = self.__packet_all[14:18]
      self.__packet['target_mac_addr'] = self.__packet_all[18:24]
      self.__packet['target_ip_addr'] = self.__packet_all[24:]
    else:
      raise TypeError('A megadott ertek nem <bytes> tipus')

  def get_packet_all(self):
    return self.__packet_all
  
  def get_element(self, element):
    return self.__packet[element]
  
  def set_element(self, element, value):
    if isinstance(value, bytes):
      if element == 'hard_type' and len(value) == 2:
        self.__packet_all = value + self.__packet_all[2:]
        return True
      if element == 'prot_type' and len(value) == 2:
        self.__packet_all = self.__packet_all[:2] + value + self.__packet_all[4:]
        return True
      if element == 'hard_size' and len(value) == 1:
        self.__packet_all = self.__packet_all[:4] + value + self.__packet_all[5:]
        return True
      if element == 'prot_size' and len(value) == 1:
        self.__packet_all = self.__packet_all[:5] + value + self.__packet_all[6:]
        return True
      if element == 'op' and len(value) == 2:
        self.__packet_all = self.__packet_all[:6] + value + self.__packet_all[8:]
        return True
      if element == 'sender_mac_addr' and len(value) == 6:
        self.__packet_all = self.__packet_all[:8] + value + self.__packet_all[14:]
        return True
      if element == 'sender_ip_addr' and len(value) == 4:
        self.__packet_all = self.__packet_all[:14] + value + self.__packet_all[18:]
        return True
      if element == 'target_mac_addr' and len(value) == 6:
        self.__packet_all = self.__packet_all[:18] + value + self.__packet_all[24:]
        return True
      if element == 'target_ip_addr' and len(value) == 4:
        self.__packet_all = self.__packet_all[:24] + value
        return True

    return False

  def reply_packet(self):
    if f.OP[self.__packet['op'].hex()] == 'ARP_request':
      arp_reply_packet = ARP_packet(self.__packet_all)
      arp_reply_packet.set_element('op', b'\x00\x02')
      arp_
    
    return b''


