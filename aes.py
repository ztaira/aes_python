# 1 byte = 8 bits
# basic processing unit = 1 byte
# bit patterns are represented in hexadecimal, eg. [0-f][0-f]
# http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
# Python bitwise operators: 
    # x >> y shift right by y places
    # x << y shift left by y places
    # x & y  bitwise and
    # x | y  bitwise or
    # ~ x    the inverse of x by switching 0 for 1 and vice-versa. -x - 1
    # x ^ y  bitwise xor
# useful things:
# gets binary value of hex
# bin(int('a', 16))
# gets value of unicode character:
# bin(ord('a'))
# hex(ord('a'))

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

        # the following byte array represents this:
        # [ 1 0 0 0 1 1 1 1 ]
        # [ 1 1 0 0 0 1 1 1 ]
        # [ 1 1 1 0 0 0 1 1 ]
        # [ 1 1 1 1 0 0 0 1 ]
        # [ 1 1 1 1 1 0 0 0 ]
        # [ 0 1 1 1 1 1 0 0 ]
        # [ 0 0 1 1 1 1 1 0 ]
        # [ 0 0 0 1 1 1 1 1 ]
        self.sub_bytes_array = [143, 199, 227, 241, 248, 124, 62, 31]

        # The state array is 4x4, each index holding a single character:
        # [[ 0, 0, 0, 0]
        #  [ 0, 0, 0, 0]
        #  [ 0, 0, 0, 0]
        #  [ 0, 0, 0, 0]]
        self.state_array = [['']*4, ['']*4, ['']*4, ['']*4]
        print self.state_array

    def write_hex_file(self, file_name):
        """
        Changes a file into hex. 16 characters per line for readability.
        """
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

    def write_encoded_file(self, file_name):
        """Encodes a file using AES."""
        with open(str(file_name), 'r') as work_file:
            with open('encodedfile.txt', 'w') as encoded_file:
                self.print_state_array()
                # while self.get_input_from_file(work_file):
                while self.get_input_from_hex_file(work_file):
                    self.sub_bytes()
                    self.shift_rows()
                    self.mix_columns()
                    self.add_round_key()
                    print ''
                    self.print_state_array()

    def get_input_from_file(self, work_file):
        """Reads in 16 bytes of input from a normal text file."""
        file_ended = False
        for column in range(4):
            for row in range(4):
                char = work_file.read(1)
                if char == '':
                    char = 'Z'
                    file_ended = True
                hex_char = hex(ord(char))[2:]
                if len(hex_char) == 1:
                    hex_char = '0' + hex_char
                self.state_array[row][column] = hex_char
        return not file_ended

    def get_input_from_hex_file(self, hex_file):
        """Reads in 16 bytes of input from a text file with hex values."""
        file_ended = False
        line = hex_file.readline()
        hex_list = line.split()
        for index in range(len(hex_list)):
            row = index % 4
            column = index / 4
            self.state_array[row][column] = hex_list[index]
        self.print_state_array()

    def sub_bytes(self):
        """AES SubBytes() transformation"""
        sbox_calc_list = []
        for row in range(4):
            for column in range(4): 
                print "Before sub_bytes(", row, column, ")"
                self.print_state_array()
                char = int(self.state_array[row][column], 16)
                print 'first char in decimal:', char
                # don't need this for some reason
                # char = ~char
                sbox_calc_list = []
                final_bit = 0
                final_byte = ''
                # after this for loop, sbox_calc_list should look like this:
                # ['11110000'
                #  '10101010'
                #  '10111101'
                #  '00011010'
                #  '10010101'
                #  '10100100'
                #  '10000110'
                #  '01000111']
                for number in self.sub_bytes_array:
                    bit_string = bin(char & number)[2:]
                    while len(bit_string) < 8:
                        bit_string = '0' + bit_string
                    sbox_calc_list.append(bit_string)
                print "sbox_calc_list: ", sbox_calc_list
                # after this for loop, sbox_calc_list should look like this:
                # [1,
                #  1,
                #  1,
                #  0,
                #  1,
                #  1,
                #  1,
                #  0]
                for sbox_string in range(8):
                    final_bit = 0
                    for sbox_char in range(8):
                        final_bit = final_bit ^ int(sbox_calc_list[sbox_string][sbox_char])
                    sbox_calc_list[sbox_string] = final_bit
                # After this loop, final_byte should be a string:
                # '00101000'
                for final_bit in range(8):
                    final_byte = str(sbox_calc_list[final_bit]) + final_byte
                final_byte = self.cut_prefix_string(hex(int(final_byte, 2)), 2)
                print 'final byte in hex:', final_byte
                self.state_array[row][column] = final_byte
                print "After sub_bytes(", row, column, ")"
                self.print_state_array()
                print ''

    def shift_rows(self):
        """AES ShiftRows() Transformation"""
        pass
    
    def mix_columns(self):
        """AES MixColumns() Transformation"""
        pass
    
    def add_round_key(self):
        """AES AddRoundKey() Transformation"""
        pass

    def print_state_array(self):
        """Prints out the state array"""
        for row in range(4):
            for column in range(4):
                print '| ', self.state_array[row][column], '  ',
            print '|'

    def cut_prefix_string(self, number_string, length):
        """Cuts out the 0x and 0b from the hex/bin method strings"""
        return_string = number_string[2:]
        while len(return_string) < length:
            return_string = '0' + return_string
        return return_string

    def print_delimiter(self):
        """Prints a delimiter"""
        print '# ==============================================================================================================================================='
        print '#  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\\'
        print '# /  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \/  \\'
        print '# ==============================================================================================================================================='

if __name__ == '__main__':
    x = aes_object(128)
    x.write_hex_file('helloworld.txt')
    x.print_delimiter()
    x.write_encoded_file('hexfile.txt')
