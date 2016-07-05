# 1 byte = 8 bits
# basic processing unit = 1 byte
# bit patterns are represented in hexadecimal, eg. [0-f][0-f]
# http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf

class aes_object():
    def __init__(self, cipher_key_bit_length):
        # cipher key length is 128, 192, or 256 bits
        # aka 16, 24, or 32 bytes
        self.cipher_key_length_bits = int(cipher_key_bit_length)
        self.cipher_key_length_bytes = int(cipher_key_bit_length) / 8

        # block size is 128 bits
        # aka 16 bytes
        self.block_size_bits = 128
        self.block_size_bytes = 16
        
        # The AES algorithm operations are performed on a 2D array called the
        # State, which consists of four rows of Nb bytes, where Nb is the block
        # length divided by 32. In this case, the block length (number of bits
        # in a block) is constant at 128, so Nb is 128 / 32 = 4. 

        # The number of rounds in the AES, Nr, is determined by the number of 
        # 32-bit words (Nk) in the cipher key. 
        self.Nr = 0
        if self.cipher_key_length_bits / 32 == 4:
            self.Nr = 10
        elif self.cipher_key_length_bits / 32 == 6:
            self.Nr = 12
        elif self.cipher_key_length_bits / 32 == 8:
            self.Nr = 14
        else:
            message = "Invalid cipher key size: " + \
                      str(self.cipher_key_length_bits) + \
                      " bits"
            raise ValueError(message)
    
    def write_hex_file(self, file_name):
        count = 0;
        with open(str(file_name), 'r') as work_file:
            with open('hexfile.txt', 'w') as hex_file:
                for char in iter(lambda: work_file.read(1), ''):
                    hex_char = hex(ord(char))[2:]
                    if len(hex_char) == 1:
                        hex_char = '0' + hex_char
                    hex_file.write(hex_char)
                    count = count+1
                    if count == 16:
                        hex_file.write('\n')
                        count = 0
                    else:
                        hex_file.write(' ')

    def sub_bytes(self):
        pass

    def shift_rows(self):
        pass
    
    def mix_columns(self):
        pass
    
    def add_round_key(self):
        pass

    def bytes_to_array():
        # useful things:
        # gets binary value of hex
        # bin(int('a', 16))
        # gets value of unicode character:
        # bin(ord('a'))
        # hex(ord('a'))
        pass

if __name__ == '__main__':
    x = aes_object(128)
    x.write_hex_file('helloworld.txt')
