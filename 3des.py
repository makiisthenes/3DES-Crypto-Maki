import math
# import numpy
import secrets

# DES Implementation, this is a block cipher used from 1970 to 1999 as the US Encryption Standard for government.
# 3DES Example which are used in ePassports and Hardware Constraint Cryptosystems.

# Variables
ROUNDS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]  # Key Bit Shifts

s1 = [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
      [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
      [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
      [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 00, 6, 13]]

s2 = [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
      [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
      [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
      [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]]

s3 = [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
      [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
      [13, 6, 4, 9, 8, 15, 3, 00, 11, 1, 2, 12, 5, 10, 14, 7],
      [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]]

s4 = [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
      [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
      [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
      [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]]

s5 = [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
      [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
      [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
      [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]]

s6 = [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
      [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
      [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
      [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]]

s7 = [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
      [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
      [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
      [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 00, 15, 14, 2, 3, 12]]

s8 = [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
      [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
      [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
      [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]


def decimal2binary(decimal_value):
    output = "{0:b}".format(decimal_value)
    print(output)
    # Max Length 4 bits.
    if len(output) != 64:
        binary_padding = 64 - len(output)
        output += (binary_padding * '0')
    return output

def decimal2nibble(decimal_value):
    output = "{0:b}".format(decimal_value)
    print(output)
    # Max Length 4 bits.
    if len(output) != 4:
        binary_padding = 4 - len(output)
        output += (binary_padding * '0')
    return output


def tobits(s):
    result = []
    for c in s:
        bits = bin(ord(c))[2:]
        bits = '00000000'[len(bits):] + bits
        result.extend([int(b) for b in bits])
    return result


def frombits(bits):
    chars = []
    for b in range(math.ceil(len(bits) / 8)):
        byte = bits[b*8:(b+1)*8]
        chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
    return ''.join(chars)


def init_key_schedule(key):
    # 56 bit encryption key derivation from 64 key [string]
    if len(key) != 64:
        print("Key Length is: " + str(len(key)))
        print("Key must be 64 bits long!!")
        exit(0)
    else:
        d = list(key)
        perm_key_array = [d[57-1], d[49-1], d[41-1], d[33-1], d[25-1], d[17-1], d[9-1], d[1-1],
                          d[58-1], d[50-1], d[42-1], d[34-1], d[26-1], d[18-1], d[10-1], d[2-1],
                          d[59-1], d[51-1], d[43-1], d[35-1], d[27-1], d[19-1], d[11-1], d[3-1],
                          d[60-1], d[52-1], d[44-1], d[36-1], d[63-1], d[55-1], d[47-1], d[39-1],
                          d[31-1], d[23-1], d[15-1], d[7-1], d[62-1], d[54-1], d[46-1], d[38-1],
                          d[30-1], d[22-1], d[14-1], d[6-1], d[61-1], d[53-1], d[45-1], d[37-1],
                          d[29-1], d[21-1], d[13-1], d[5-1], d[28-1], d[20-1], d[12-1], d[4-1]]
        return perm_key_array


def key_generator():
    key = secrets.randbits(64)  # 64 Bit Key (8 bytes)
    key = decimal2binary(key)
    return key


def key_permutation(d):
    key48 = [d[14-1], d[17-1], d[11-1], d[24-1], d[1-1], d[5-1], d[3-1], d[28-1],
             d[15-1], d[6-1], d[21-1], d[10-1], d[23-1], d[19-1], d[12-1], d[4-1],
             d[26-1], d[8-1], d[16-1], d[7-1], d[27-1], d[20-1], d[13-1], d[2-1],
             d[41-1], d[52-1], d[31-1], d[37-1], d[47-1], d[55-1], d[30-1], d[40-1],
             d[51-1], d[45-1], d[33-1], d[48-1], d[44-1], d[49-1], d[39-1], d[56-1],
             d[34-1], d[53-1], d[46-1], d[42-1], d[50-1], d[36-1], d[29-1], d[32-1]]
    return key48


def plaintext_permutation(d):
    # Initial Permutation at Start of 16 Rounds
    perm_array = [d[58 - 1], d[50 - 1], d[42 - 1], d[34 - 1], d[26 - 1], d[18 - 1], d[10 - 1], d[2 - 1],
                  d[60 - 1], d[52 - 1], d[44 - 1], d[36 - 1], d[28 - 1], d[20 - 1], d[12 - 1], d[4 - 1],
                  d[62 - 1], d[54 - 1], d[46 - 1], d[38 - 1], d[30 - 1], d[22 - 1], d[14 - 1], d[6 - 1],
                  d[64 - 1], d[56 - 1], d[48 - 1], d[40 - 1], d[32 - 1], d[24 - 1], d[16 - 1], d[8 - 1],
                  d[57 - 1], d[49 - 1], d[41 - 1], d[33 - 1], d[25 - 1], d[17 - 1], d[9  - 1], d[1 - 1],
                  d[59 - 1], d[51 - 1], d[43 - 1], d[35 - 1], d[27 - 1], d[19 - 1], d[11 - 1], d[3 - 1],
                  d[61 - 1], d[53 - 1], d[45 - 1], d[37 - 1], d[29 - 1], d[21 - 1], d[13 - 1], d[5 - 1],
                  d[63 - 1], d[55 - 1], d[47 - 1], d[39 - 1], d[31 - 1], d[23 - 1], d[15 - 1], d[7 - 1]]
    return perm_array


def ciphertext_permutation(d):
    # Inverse Permutation at End of 16 Rounds
    perm_array = [d[40 - 1], d[8 - 1], d[48 - 1], d[16 - 1], d[56 - 1], d[24 - 1], d[64 - 1], d[32 - 1],
                  d[39 - 1], d[7 - 1], d[47 - 1], d[15 - 1], d[55 - 1], d[23 - 1], d[63 - 1], d[31 - 1],
                  d[38 - 1], d[6 - 1], d[46 - 1], d[14 - 1], d[54 - 1], d[22 - 1], d[62 - 1], d[30 - 1],
                  d[37 - 1], d[5 - 1], d[45 - 1], d[13 - 1], d[53 - 1], d[21 - 1], d[61 - 1], d[29 - 1],
                  d[36 - 1], d[4 - 1], d[44 - 1], d[12 - 1], d[52 - 1], d[20 - 1], d[60 - 1], d[28 - 1],
                  d[35 - 1], d[3 - 1], d[43 - 1], d[11 - 1], d[51 - 1], d[19 - 1], d[59 - 1], d[27 - 1],
                  d[34 - 1], d[2 - 1], d[42 - 1], d[10 - 1], d[50 - 1], d[18 - 1], d[58 - 1], d[26 - 1],
                  d[33 - 1], d[1 - 1], d[41 - 1], d[9  - 1], d[49 - 1], d[17 - 1], d[57 - 1], d[25 - 1]]
    return perm_array


def right_block_expansion(d):
    array = [d[32-1], d[1-1], d[2-1], d[3-1], d[4-1], d[5-1],
             d[4-1], d[5-1], d[6-1], d[7-1], d[8-1], d[9-1],
             d[8-1], d[9-1], d[10-1], d[11-1], d[12-1], d[13-1],
             d[12-1], d[13-1], d[14-1], d[15-1], d[16-1], d[17-1],
             d[16-1], d[17-1], d[18-1], d[19-1], d[20-1], d[21-1],
             d[20-1], d[21-1], d[22-1], d[23-1], d[24-1], d[25-1],
             d[24-1], d[25-1], d[26-1], d[27-1], d[28-1], d[29-1],
             d[28-1], d[29-1], d[30-1], d[31-1], d[32-1], d[1-1]]
    return array

def bit_extracter(bit_array):
    column = int(str(bit_array[1])+str(bit_array[2])+str(bit_array[3])+str(bit_array[4]), 2)
    row  = int(str(bit_array[0])+str(bit_array[5]), 2)
    return column, row


def end_perm_function(d):
    s_block32 = [d[16-1], d[7-1], d[20-1], d[21-1], d[29-1], d[12-1], d[28-1], d[17-1],
                 d[1-1], d[15-1], d[23-1], d[26-1], d[5-1], d[18-1], d[31-1], d[10-1],
                 d[2-1], d[8-1], d[24-1], d[14-1], d[32-1], d[27-1], d[3-1], d[9-1],
                 d[19-1], d[13-1], d[30-1], d[6-1], d[22-1], d[11-1], d[4-1], d[25-1]]
    return s_block32

def nibble_padding(nibble):
    # print("Length of nibble: "+ str(len(nibble)))
    # print("Nibble: "+ nibble)
    if len(nibble) != 4:
        nibble+=('0'*(4-len(nibble)))
    return nibble

def funcf(left_block, right_block, subkey):
    # Right Block Consists of 32 bits
    array = right_block_expansion(right_block)
    int_key = []
    for x in range(len(array)):
        # XOR Operation
        int_key.append((int(array[x]) + int(subkey[x])) % 2)
    s1bits = int_key[:6]
    s1c, s1r = bit_extracter(s1bits)
    nibble1 = nibble_padding(str(decimal2nibble(s1[s1r][s1c])))
    s2bits = int_key[6:12]
    s2c, s2r = bit_extracter(s2bits)
    nibble2 = nibble_padding(str(decimal2nibble(s2[s2r][s2c])))
    s3bits = int_key[12:18]
    s3c, s3r = bit_extracter(s3bits)
    nibble3 = nibble_padding(str(decimal2nibble(s3[s3r][s3c])))
    s4bits = int_key[18:24]
    s4c, s4r = bit_extracter(s4bits)
    nibble4 = nibble_padding(str(decimal2nibble(s4[s4r][s4c])))
    s5bits = int_key[24:30]
    s5c, s5r = bit_extracter(s5bits)
    nibble5 = nibble_padding(str(decimal2nibble(s5[s5r][s5c])))
    s6bits = int_key[30:36]
    s6c, s6r = bit_extracter(s6bits)
    nibble6 = nibble_padding(str(decimal2nibble(s6[s6r][s6c])))
    s7bits = int_key[36:42]
    s7c, s7r = bit_extracter(s7bits)
    nibble7 = nibble_padding(str(decimal2nibble(s7[s7r][s7c])))
    s8bits = int_key[42:48]
    s8c, s8r = bit_extracter(s8bits)
    nibble8 = nibble_padding(str(decimal2nibble(s8[s8r][s8c])))
    s_block32 = list(nibble1+nibble2+nibble3+nibble4+nibble5+nibble6+nibble7+nibble8)
    s_block32 = end_perm_function(s_block32)
    new_right = []
    for x in range(len(left_block)):
         new_right.append(((int(left_block[x]) + int(s_block32[x])) % 2))
    return new_right


def DES(bits):
    des_cipher = []
    message_bit_length = len(bits)
    encrypt_blocks = math.ceil(message_bit_length/64)
    key = str(key_generator())
    original_key = key
    print("Your Encryption Key is : " + key)
    print("The Initial Key Length is: " + str(len(key)))
    for block_increment in range(1, encrypt_blocks+1):
        print("Bit Block " + str(block_increment))
        bit_array = bits[(64*(block_increment-1)):(64*block_increment)]
        if len(bit_array) != 64:
            pad_req = 64 - len(bit_array)
            for x in range(pad_req):
                bit_array.append(0)

        # Permutation and Splitting of PlainText
        print("Original Plain Text: "+ frombits(bit_array))
        bit_array = plaintext_permutation(bit_array)  # Bits Permutation
        print("Permutation Plain Text: "+ frombits(bit_array))
        left_block = bit_array[:32]         # Bits Split into 32 L
        right_block = bit_array[32:]        # Bits Split into 32 R
        print("Left Block:  " + str(left_block))
        print("Right Block: " + str(right_block))

        # Permutation and Splitting of Key
        if block_increment == 1:
            key = init_key_schedule(key)
            # Make it 54 bits long list.

        for current_round in range(16):
            # Key is split into 2 parts list.
            c_key = key[:28]
            d_key = key[28:]
            print("C Key: " + str(c_key))
            print("D Key: " + str(d_key))
            print("Subkey: " + str(key))
            # print("key value" + str(c_key))
            print("Round: " + str(current_round+1))
            bit_shift = ROUNDS[current_round]
            print("Bit shift: " + str(bit_shift))
            if bit_shift ==1:
                # Shift bits to left by 1;
                c_key.append(c_key.pop(0))
                d_key.append(d_key.pop(0))
            else:
                # Shift bits to left by 2;
                c_key.append(c_key.pop(0))
                c_key.append(c_key.pop(0))
                d_key.append(d_key.pop(0))
                d_key.append(d_key.pop(0))
            print("C Key: " + str(c_key))
            print("D Key: " + str(d_key))
            key = c_key + d_key  # 56 Bit Key
            print("Subkey: " + str(key))
            key48 = key_permutation(key)
            new_right = funcf(left_block, right_block, key48)
            left_block = right_block
            right_block = new_right

        # End of rounds and now we to inverse permutation and DES CipherText is Output.
        final_block = right_block + left_block
        des_cipher = ciphertext_permutation(final_block)
        des_cipher+=des_cipher
        return des_cipher, original_key


DES_keys = []
message = input("Enter a message to be encrypted with DES:: ")
bits = tobits(message)
des_cipher, original_key = DES(bits)
print("Full Encrypted Cipher in Bits = "+ str(des_cipher))
print("Full Encrypted Cipher in ASCII = "+ frombits(des_cipher))
print("Original Key for this DES1 is: " + original_key)
des_cipher, original_key = DES(bits)
print("Full Encrypted Cipher in Bits = "+ str(des_cipher))
print("Full Encrypted Cipher in ASCII = "+ frombits(des_cipher))
print("Original Key for this DES2 is: " + original_key)
des_cipher, original_key = DES(bits)
print("Full Encrypted Cipher in Bits = "+ str(des_cipher))
print("Full Encrypted Cipher in ASCII = "+ frombits(des_cipher))
print("Original Key for this DES3 is: " + original_key)
print("+--------------------------------------------------+")
print("DES3 Cipher: " + str(des_cipher))





# Your Encryption Key is : 1001110010011110101100000110001110010001011011011110011111011011
# Original Plain Text: hello
# First and Last Subkeys are equal to each other. DES Run Successfully.
# Round1 Subkey: ['1', '1', '0', '1', '0', '1', '1', '1', '1', '1', '1', '0', '1', '0', '0', '0', '0', '1', '1', '0', '1', '1',
# '0', '0', '1', '0', '0', '1', '1', '1', '0', '0', '1', '0', '1', '0', '0', '1', '1', '0', '0', '0', '1', '1', '1', '0',
# '1', '0', '0', '0', '1', '1', '0', '1', '1', '1']

# Round16 Subkey: ['1', '1', '0', '1', '0', '1', '1', '1', '1', '1', '1', '0', '1', '0', '0', '0', '0', '1', '1', '0', '1', '1',
# '0', '0', '1', '0', '0', '1', '1', '1', '0', '0', '1', '0', '1', '0', '0', '1', '1', '0', '0', '0', '1', '1', '1', '0',
# '1', '0', '0', '0', '1', '1', '0', '1', '1', '1']

# Full Encrypted Cipher in Bits = [0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1,
# 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0,
# 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0,
# 0, 0, 1, 0, 1, 0, 1, 1, 1, 0]

# Full Encrypted Cipher in ASCII = 	É50®	É50®
