import pytest
from dynamic_sse.tools.decorators import str_to_bytes

def test_str_to_bytes():
    
    @str_to_bytes('y')
    def mock_func(y : bytes):
        assert type(y) is bytes

    mock_func(y='hello')