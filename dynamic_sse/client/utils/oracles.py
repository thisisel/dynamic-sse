from cryptography.hazmat.primitives import hashes


class RandOracles:
    @classmethod
    def hx(cls, data: bytes, length: int):
        hash_obj = hashes.Hash(hashes.SHA512())

        copy_hash_obj = hash_obj.copy()
        copy_hash_obj.update(data)
        first_digest = copy_hash_obj.finalize()

        concatenated_digest: bytes = first_digest
        while length > len(concatenated_digest):
            concatenated_digest += first_digest
        return concatenated_digest[:length]
