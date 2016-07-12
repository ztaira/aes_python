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
    def __init__(self, input_cipher_key):
        # cipher key length is 128, 192, or 256 bits
        # aka 16, 24, or 32 bytes
        self.cipher_key = [int(input_cipher_key[i:i+2], 16) for i in range(0, len(input_cipher_key), 2)]
        self.cipher_key_length_bits = len(self.cipher_key) * 8
        self.cipher_key_length_bytes = len(self.cipher_key)

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
        if self.cipher_key_length_bytes == 16:
            self.Nr = 10
        elif self.cipher_key_length_bytes  == 24:
            self.Nr = 12
        elif self.cipher_key_length_bytes  == 32:
            self.Nr = 14
        else:
            message = "Invalid cipher key size: " + \
                      str(self.cipher_key_length_bytes) + \
                      " bytes"
            raise ValueError(message)

        # This array is the sbox, which gets populated via get_sbox()
        self.sbox = {}
        
        # This array is to be used for mix_columns()
        self.mix_columns_array = [
            [2, 3, 1, 1],
            [1, 2, 3, 1],
            [1, 1, 2, 3],
            [3, 1, 1, 2]]

        # The state array is 4x4, each index holding a single hex character:
        # [[ 0, 0, 0, 0]
        #  [ 0, 0, 0, 0]
        #  [ 0, 0, 0, 0]
        #  [ 0, 0, 0, 0]]
        self.state_array = [['']*4, ['']*4, ['']*4, ['']*4]

        # This is 1d list of the rcon values 
        self.rcon = []
        
        # The expanded key
        self.expanded_key = ''

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
        self.get_sbox()
        self.get_rcon()
        self.generate_expanded_key()
        with open(str(file_name), 'r') as work_file:
            with open('encodedfile.txt', 'w') as encoded_file:
                # while self.get_input_from_file(work_file):
                while self.get_input_from_hex_file(work_file):
                    self.sub_bytes()
                    self.shift_rows()
                    self.mix_columns()
                    self.add_round_key()
                    print ''
                    self.print_delimiter

    def get_input_from_file(self, work_file):
        """Reads in 16 bytes of input from a normal text file."""
        file_ended = False
        for column in range(4):
            for row in range(4):
                char = work_file.read(1)
                if char == '':
                    char = 'Z'
                    file_ended = True
                self.state_array[row][column] = ord(char)
        return not file_ended

    def get_input_from_hex_file(self, hex_file):
        """Reads in 16 bytes of input from a text file with hex values."""
        file_ended = False
        line = hex_file.readline()
        if line == '':
            file_ended = True
        hex_list = line.split()
        for index in range(len(hex_list)):
            row = index % 4
            column = index / 4
            self.state_array[row][column] = int(hex_list[index], 16)
        print "Read in the following values from hex file:"
        self.print_state_array()
        return not file_ended

    def generate_expanded_key(self):
        """Expands the cipher key"""
        self.expanded_key = self.cipher_key[0:self.cipher_key_length_bytes]
        final_key_size = 0
        print "Cipher/Expanded Key Length:", len(self.expanded_key)
        print "Cipher/Expanded Key:"
        self.print_list_as_hex(self.expanded_key)
        rcon_iter = 1
        if self.cipher_key_length_bytes == 16:
            final_key_size = 176
        elif self.cipher_key_length_bytes == 24:
            final_key_size = 208
        elif self.cipher_key_length_bytes == 32:
            final_key_size = 240
        while len(self.expanded_key) < final_key_size:
            temp = self.expanded_key[-4:]
            temp = self.key_core(temp, rcon_iter)
            rcon_iter = rcon_iter+1
            temp = self.key_schedule_xor(temp)
            self.expanded_key += temp
            print "Length of Expanded Key:", len(self.expanded_key)
            self.print_list_as_hex(self.expanded_key)
            print ''
            print ''
            for i in range(3):
                temp = self.expanded_key[-4:]
                temp = self.key_schedule_xor(temp)
                self.expanded_key += temp
                print "temp word:"
                self.print_list_as_hex(temp)
                print "Length of Expanded Key:", len(self.expanded_key)
                print "Expanded key:"
                self.print_list_as_hex(self.expanded_key)
                print ''

    def key_core(self, temp, rcon_iter):
        """AES key schedule core, used in key expansion"""
        # convert to a list
        return_value = temp
        print 'key core:'
        self.print_list_as_hex(return_value)
        # rotate the output one bit left
        return_value = return_value[1:] + return_value[0:1]
        print 'rot_word:'
        self.print_list_as_hex(return_value)
        # apply sbox on all four bytes
        for byte in range(4):
            return_value[byte] = self.sbox[return_value[byte]]
        print 'sub_word:'
        self.print_list_as_hex(return_value)
        return_value[0] = return_value[0] ^ (self.rcon[rcon_iter])
        print "post_xor:"
        self.print_list_as_hex(return_value)
        return return_value

    def key_schedule_xor(self, temp):
        """AES key schedule xor function"""
        # converts from hex strings like 'a1e12e3d' to ints and then back again
        distance = -self.cipher_key_length_bytes
        list1 = self.expanded_key[distance:(distance+4)]
        print "xoring this word and temp array:"
        self.print_list_as_hex(list1)
        self.print_list_as_hex(temp)
        results = []
        for i in range(4):
           results.append(list1[i] ^ temp[i])
        return results

    def sub_bytes(self):
        """AES SubBytes() transformation"""
        sbox_calc_list = []
        for row in range(4):
            for column in range(4): 
                num = self.state_array[row][column]
                self.state_array[row][column] = self.sbox[num]
        print "After sub_bytes()"
        self.print_state_array()

    def get_sbox(self):
        """Gets the s-box from a text file and puts it in a dict"""
        self.sbox = []
        with open('sbox.txt', 'r') as sbox_file:
            lines = sbox_file.read().splitlines()  
        linenum = 0
        for line in lines: 
            self.sbox = self.sbox + line.split()
        for value in range(len(self.sbox)):
            self.sbox[value] = int(self.sbox[value], 16)

    def get_rcon(self):
        """Gets the rcon list from a text file"""
        self.rcon = []
        with open('rcon.txt', 'r') as rcon_file:
            lines = rcon_file.read().splitlines()
        for line in lines:
            self.rcon = self.rcon + line.split()
        for value in range(len(self.rcon)):
            self.rcon[value] = int(self.rcon[value], 16)

    def shift_rows(self):
        """AES ShiftRows() Transformation"""
        for row_num in range(4):
            for shift in range(row_num):
                shift_num = self.state_array[row_num].pop(0)
                self.state_array[row_num].append(shift_num)
        print "After shift_rows():"
        self.print_state_array()
    
    def mix_columns(self):
        """AES MixColumns() Transformation"""
        # for row in range(4):
            # for column in range(4):
                # self.state_array[row][column] = int(self.state_array[row][column], 16)
        for column in range(4):
            # puts a column of the state array into mix_row
            mix_row = []
            for row in range(4):
                mix_row.append(self.state_array[row][column])
            # does math to calculate result for each box
            for row in range(4):
                self.mix_column(mix_row, column, row)
        print "After mix_columns():"
        self.print_state_array()

    def mix_column(self, mix_row, column, row):
        """Mixes a single column"""
        temp_array = self.mix_columns_array[row]
        # print temp_array, column, row
        # print mix_row
        results_list = []
        result = 0
        for x in range(4):
            if temp_array[x] == 1:
                results_list.append(mix_row[x])
            elif temp_array[x] == 2:
                if self.cut_prefix_string(bin(mix_row[x]), 8)[0:1] == '1':
                    results_list.append(((mix_row[x] << 1) - 256) ^ 27)
                else:
                    results_list.append((mix_row[x] << 1))
            elif temp_array[x] == 3: 
                if self.cut_prefix_string(bin(mix_row[x]), 8)[0:1] == '1':
                    results_list.append((((mix_row[x] << 1) - 256) ^ 27) ^ mix_row[x])
                else:
                    results_list.append((mix_row[x] << 1) ^ mix_row[x])
        # for x in range(4):
            # print self.cut_prefix_string(bin(results_list[x]), 8)
        result = results_list[0] ^ results_list[1] ^ results_list[2] ^ results_list[3]
        # print hex(result), result
        self.state_array[row][column] = result
    
    def add_round_key(self):
        """AES AddRoundKey() Transformation"""
        pass

    def print_state_array(self):
        """Prints out the state array"""
        print "State Array:"
        for row in range(4):
            self.print_list_as_hex(self.state_array[row])
        print ""

    def print_list_as_hex(self, int_list):
        """prints out the expanded key"""
        for item in range(len(int_list)):
            print self.cut_prefix_string(hex(int_list[item]), 2),
            if (item + 1) % 16 == 0:
                print ''
        print ''

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
    # x = aes_object('2b7e151628aed2a6abf7158809cf4f3c')
    # x = aes_object('00000000000000000000000000000000')
    # x = aes_object('ffffffffffffffffffffffffffffffff')
    # x = aes_object('000102030405060708090a0b0c0d0e0f')
    x = aes_object('6920e299a5202a6d656e636869746f2a')
    # x.write_hex_file('helloworld.txt')
    x.print_delimiter()
    x.write_encoded_file('hexfile.txt')
