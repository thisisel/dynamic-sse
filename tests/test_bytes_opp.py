import pytest
from dynamic_sse.tools import BytesOpp

@pytest.mark.parametrize(
    "expected , inputs",
    [
        (b'\x01\x01\x01\x01', (b'\x00\x00\x01\x01',b'\x01\x01\x00\x00')),
    ],
)
def test_xor(inputs, expected):
    r = BytesOpp.xor_bytes(a=inputs[0], b=inputs[1])

    assert r == expected
    assert BytesOpp.eq_bytes(r,expected) == True


