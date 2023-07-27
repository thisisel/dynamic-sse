from os import urandom
from dynamic_sse.tools import DataTools

def test_entry_splitter():
    i = 6
    rand_x = urandom(int(i/2))
    r_hs, l_hs = DataTools.entry_splitter(entry=rand_x, split_ptr=i)

    assert len(r_hs) == i/2
    assert len(l_hs) == 0
