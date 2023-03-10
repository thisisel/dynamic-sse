
class DataTools:
    
    @classmethod
    def entry_splitter(cls, entry, split_ptr):
            l_hs = entry[:split_ptr]
            r_hs = entry[split_ptr:]
        
            return l_hs, r_hs