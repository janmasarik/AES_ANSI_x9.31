import click
import math
from tqdm import tqdm
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class AESGenerator:
    """
     DT: date/time vector
     V: seed value (secret)
     K: AES key (secret)

     All of above have to be 128-bit (for AES 128-bit).
    """
    BLOCK_SIZE = 16

    def __init__(self, seed, key):
        self.DT = 0
        self.V = seed
        self.K = key

        # WARNING: uses insecure ECB as it was required by example
        self.aes = Cipher(algorithms.AES(self.K), modes.ECB(), backend=default_backend()).encryptor()

    def __call__(self, size):
        return self.get_random_data(size)

    @staticmethod
    def xor_bytes(s1, s2):
        int_enc = int.from_bytes(s1, 'big') ^ int.from_bytes(s2, 'big')

        return int_enc.to_bytes(AESGenerator.BLOCK_SIZE, 'big')

    def get_random_data(self, size):
        """
        :param size: Size of desired random data (in bytes)
        :return: Pseudorandom binary data with desired size
        """
        result = bytearray()
        for _ in tqdm(range(math.ceil(size / 16))):
            result.extend(self.get_block())

        # truncate data to desired size
        if size % AESGenerator.BLOCK_SIZE != 0:
            result = result[:-(AESGenerator.BLOCK_SIZE - (size % AESGenerator.BLOCK_SIZE))]

        return result


    def get_block(self):
        """
        Get block of pseudo-random data.
        Naming of variables as defined in
        https://web.archive.org/web/20140813123026/http://csrc.nist.gov/groups/STM/cavp/documents/rng/931rngext.pdf

        :return: Block of pseudo-randomly generated data.
        """
        try:
            dt_bytes = self.DT.to_bytes(self.BLOCK_SIZE, 'big')
        except OverflowError:
            self.DT = 0
            dt_bytes = self.DT.to_bytes(self.BLOCK_SIZE, 'big')

        I = self.aes.update(dt_bytes)
        self.DT += 1

        R = self.aes.update(self.xor_bytes(I, self.V))

        self.V = self.aes.update(self.xor_bytes(R, I))

        return R


def transform_string(s):
    """We need to treat key / seed as hexadecimal characters, not ASCII"""
    return bytes(bytearray([int(i) for i in s]))


@click.command()
@click.option('--out', help='Path of output file')
@click.option('--size', default=1337, help='Size of data in bytes')
@click.option('--seed', help='Seed (16bytes). Will be converted to string of hexadecimal representations.')
@click.option('--key', help='Key (16bytes). Will be converted to string of hexadecimal representations.')
def generate(out, size, seed, key):
    with open(out, 'wb') as output_file:
        output_file.write(AESGenerator(transform_string(seed), transform_string(key))(size))


if __name__ == '__main__':
    generate()