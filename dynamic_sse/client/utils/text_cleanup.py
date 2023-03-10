import re
from typing import List

def tokenize_text(corpus : str) -> List[str]:
    clean_text = re.sub(r"[^A-Za-z0-9\s]+", "", corpus.lower())
    
    tokens = [t for t in clean_text.split()]
    
    return tokens