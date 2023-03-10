import os
from typing import Optional
from dotenv import load_dotenv

load_dotenv()


PLAIN_DIR = os.getenv('PLAIN_DIR') or r''
ENCODED_DIR = os.getenv('ENCODED_DIR') or r''
