from typing import Tuple
from log import get_logger

logger = get_logger(__name__)

class DataTools:
    
    @classmethod
    def entry_splitter(cls, entry: bytes, split_ptr: int)-> Tuple[bytes, bytes]:
            if not entry:
                  logger.error("entry is none")
                  raise TypeError()
            l_hs = entry[:split_ptr]
            r_hs = entry[split_ptr:]
        
            return l_hs, r_hs