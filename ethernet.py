#import struct
import formatting

class Ether_frame:
  '''
  Ethernet keret bytes()
  '''
  def __init__(self, _frame):
    '''
    inicializalo adat vizsgalata
    src_mac
    dst_mac
    eth_type
    data
    '''
    self.__frame_all = bytes()
    self.__frame = dict()
    if isinstance(_frame, bytes):
      self.__frame_all = _frame
      self.__frame['dst_mac'] = self.__frame_all[:6]
      self.__frame['src_mac'] = self.__frame_all[6:12]
      self.__frame['type'] = self.__frame_all[12:14]
      self.__frame['data'] = self.__frame_all[14:]
    else:
      raise TypeError('Megadott ertek nem <bytes> tipus')

  def get_frame_all(self):
    return self.__frame_all
  
  def get_element(self, element):
    return self.__frame[element]

  def set_element(self, element, value):
    if isinstance(value, bytes):
      if element == 'dst_mac' and len(value) == 6:
        self.__frame_all = value + self.__frame_all[6:]
        return True
      elif element == 'src_mac' and len(value) == 6:
        self.__frame_all = self.__frame_all[:6] + value + self.__frame_all[12:]
        return True
      elif element == 'type' and len(value) == 2:
        self.__frame_all = self.__frame_all[:12] + value + self.__frame_all[14:]
        return True
      elif element == 'data' and len(value) > 0:
        self.__frame_all = self.__frame_all[:14] + value
        return True
    return False