import pathlib
from typing import List, Tuple
import re
from string import punctuation

from dynamic_sse.tools import PyUnicodeObject
from log import get_logger

logger = get_logger(__name__)


class FileTools:
    @classmethod
    def get_dir_files_stats(cls, dir_path: str) -> Tuple[int, int]:
        d_path = pathlib.Path(dir_path)

        total_size = 0
        total_files = 0
        for entry in d_path.iterdir():
            if entry.is_file():
                total_files += 1
                f_size = entry.stat().st_size
                total_size += f_size

        return total_files, total_size


    @classmethod
    def chunk_reader(cls, f_ptr, chunk_size : int = 400):
        """
        f_ptr (BufferedReader)

        chunk_size guide:
            4 bytes per char (UCS-4 encoding)-> read 100 chars
            2 bytes per char (UCS-2 encoding)-> read 200 chars
            1 byte per char (Latin-1 encoding)-> read 400 chars (default) 
        """

        chunk = f_ptr.read(chunk_size)

        if not chunk:
            return None

        if type(chunk) == str:
            while chunk[-1] not in punctuation and not chunk[-1].isspace():
                bytes_per_char = PyUnicodeObject.get_str_kind(chunk[-1])
                if not (last_char := f_ptr.read(bytes_per_char)):
                    break
                chunk += last_char

        return chunk

    @classmethod
    def tokenize_txt_file(cls, file_path) -> List[str] | None:
        file_tokens = []
        stop_words = ["a"]

        try:
            with open(file_path, "r") as corpus_file:

                while chunk := cls.chunk_reader(corpus_file):
                    clean_chunk = re.sub(r"[^A-Za-z0-9\s]+", "", chunk.lower())
                    chunk_tokens = [t for t in clean_chunk.split() if t not in stop_words]
                    file_tokens.extend(chunk_tokens)

            return file_tokens
        
        except FileNotFoundError:
            logger.debug(f'{file_path} was not found')
            return



if __name__ == "__main__":
    tokens = FileTools.tokenize_txt_file(
        r"/home/elahe/Projects/Python/dynamic_sse/tests/test_data/plain/four.txt"
    )
    print(tokens)
    # print(punctuation)
