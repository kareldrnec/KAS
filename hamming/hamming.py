import argparse
import os.path
import array as arr
import re
import numpy as np

# Huffman Coding (8,4) / Huffman Decoding with error correction

# global variables
# CRC32 variables
polynomial_32 = 0xEDB88320
init = 0xffffffff
_ran = True
tab32 = []

# global variable, which indicates number of errors
num_errors = 0

# control matrix H
control_matrix = np.array([[1, 0, 1, 1, 1, 0, 0],
                           [1, 1, 1, 0, 0, 1, 0],
                           [0, 1, 1, 1, 0, 0, 1]])


def main(input_args):
    if input_args.m == "k":
        with open(input_args.i, "r") as first_file:
            for piece in read_in_chunks(first_file):
                hamming_code(piece, input_args.o)
            first_file.close()
    elif input_args.m == "d":
        with open(input_args.i, "rb") as first_file:
            while True:
                read_bytes = first_file.read(8200)
                if not read_bytes:
                    break
                hamming_decode(read_bytes, input_args.o)
        first_file.close()


def read_in_chunks(file_to_read, chunk_size=4096):
    # reads from txt file with specific chunk_size
    while True:
        data = file_to_read.read(chunk_size)
        if not data:
            break
        yield data


def hamming_code(piece_of_text, output_file):
    # transforms piece of text into bitstring
    bitstring_text = convert_chunk_into_bitstring(piece_of_text)

    # transformed text into list of substring with size of 4
    substring_arr = re.findall('....', bitstring_text)

    # bitstring transformed into bitstring, which contains hamming codes already
    coded_hamming = bits2hamming(substring_arr)

    # coded data into list of subdata with length of 8
    list_coded = re.findall('........', coded_hamming)

    # data to list of integers for CRC
    list_int = list()
    for item in list_coded:
        list_int.append(int(item, 2))

    # calculated CRC32 in int
    crc_int = calc_crc32(list_int)

    # CRC32 from int to binary
    crc_in_binstring = format(crc_int, '08b')

    # fill zeros if needed
    to_fill = 32 - len(crc_in_binstring)
    for _ in range(0, to_fill):
        crc_in_binstring = "0" + crc_in_binstring

    # CRC32 in bitstring into list of chunks with length of 4
    crc_array = re.findall('....', crc_in_binstring)

    # CRC32 bitstring into Hamming code(8,4)
    crc_hamming_code = bits2hamming(crc_array)

    # final bitstring to write
    final_string_to_write = coded_hamming + crc_hamming_code

    # if output file was included in input arguments
    if output_file:
        bytes_to_write = bitstring_into_bytes(final_string_to_write)
        write_to_bin(bytes_to_write, output_file)
    else:
        print("Data in Hamming code(8,4) from chunk of text file")
        print("-------------------------------------------------------------------------------------------------------")
        print(coded_hamming)
        print("-------------------------------------------------------------------------------------------------------")
        print("Calculated CRC32")
        print(crc_in_binstring)
        print("-------------------------------------------------------------------------------------------------------")
        print("Calculated CRC32 in Hamming code(8,4)")
        print(crc_hamming_code)
        print("-------------------------------------------------------------------------------------------------------")


def write_to_bin(bytes_to_write, output_file):
    # appends data into binary file
    with open(output_file, "ab") as file_to_write:
        file_to_write.write(bytes_to_write)
    file_to_write.close()


# CRC32 calculations
def mask32(n):
    return n & 0xffffffff


def mask8(n):
    return n & 0x000000ff


def mask1(n):
    return n & 0x00000001


def init32():
    for i in range(256):
        crc = mask32(i)
        for j in range(8):
            if mask1(crc) == 1:
                crc = mask32(mask32(crc >> 1) ^ polynomial_32)
            else:
                crc = mask32(crc >> 1)
        tab32.append(crc)
    global _ran
    _ran = False


def update32(crc, char):
    char = mask8(char)
    t = crc ^ char
    crc = mask32(mask32(crc >> 8) ^ tab32[mask8(t)])
    return crc


def calc_crc32(list_int):
    if _ran:
        init32()
    crc = init
    for char in list_int:
        crc = update32(crc, char)
    crc = crc ^ init
    return crc


def bitstring_into_bytes(bitstring):
    # bitstring into bytes
    byte_array = bytearray()
    for i in range(0, len(bitstring), 8):
        byte_array.append(int(bitstring[i:i+8], 2))
    return bytes(byte_array)


def bits2hamming(substring_arr):
    # makes huffman code (8,4) for each 4 bits of bitstring data
    result_text = ""
    for substring in substring_arr:
        result_text += fill_extra_bits(substring)
    return result_text


def fill_extra_bits(string_to_fill):
    # makes hamming code (8,4) for sub bitstring
    bit_array = arr.array('i', [])

    for char in string_to_fill:
        bit_int = int(char, 2)
        bit_array.append(bit_int)
    bit_array.append((bit_array[0] + bit_array[2] + bit_array[3]) % 2)
    bit_array.append((bit_array[0] + bit_array[1] + bit_array[2]) % 2)
    bit_array.append((bit_array[1] + bit_array[2] + bit_array[3]) % 2)

    num_zeros = bit_array.count(0)
    bit_array.append((fill_to_even(num_zeros)))

    return hamming_bitstring(bit_array)


def hamming_bitstring(arr_to_transform):
    # array of bits in integers into bitstring
    result_bitstring = ""
    for num in arr_to_transform:
        result_bitstring += str(num)
    return result_bitstring


def fill_to_even(num_zeros):
    # returns last parity bit - control bit
    result_num = 0
    if num_zeros % 2 == 0:
        result_num = 1
    return result_num


def convert_chunk_into_bitstring(piece_of_text):
    # converts piece of text into bitstring
    result_text = ""
    for char in piece_of_text:
        result_text += string_to_bin(char)
    return result_text


def string_to_bin(string):
    # returns bitstring
    return "".join(f"{ord(i):08b}" for i in string)


def write_to_txt(decoded, output):
    # writes decoded data to txt file
    with open(output, "a") as output_file:
        output_file.write(decoded)
    output_file.close()


def hamming_decode(read_bytes, output_file):
    # hamming decode
    # converts bytes to bitstring
    bitstring_from_bytes = bytes_to_bits(read_bytes)

    # original data of decoded chunk
    original_data = bitstring_from_bytes[:-64]

    # CRC32 decoded from decoded chunk
    decoded_crc = bitstring_from_bytes[-64:]

    # converts data to list of integers for CRC32 calculation
    list_int = list()
    list_coded = re.findall('........', original_data)
    for item in list_coded:
        num = int(item, 2)
        list_int.append(num)

    # CRC32 calculation - int number
    recalculated_crc_int = calc_crc32(list_int)

    # CRC32 from file
    decoded_crc = get_data_without_hamming(re.findall('........', decoded_crc))

    # recalculated CRC32 in bitstring
    recalculated_crc_bitstring = format(recalculated_crc_int, '08b')

    to_fill = 32 - len(recalculated_crc_bitstring)
    for _ in range(0, to_fill):
        recalculated_crc_bitstring = "0" + recalculated_crc_bitstring

    string_to_write = ""
    # compares CRC32 and decodes data
    if recalculated_crc_bitstring == decoded_crc:
        for i in range(0, len(list_coded)):
            list_coded[i] = check_piece_of_data(list_coded[i])
            if num_errors == 2:
                break
        if num_errors == 2:
            length_of_data = int(len(original_data) / 2)
            string_to_write = string_to_write.zfill(int(length_of_data / 8))
        else:
            string_without_hamming = get_data_without_hamming(list_coded)
            string_to_write = bitstring_into_string(string_without_hamming)
    else:
        length_of_data = int(len(original_data) / 2)
        string_to_write = string_to_write.zfill(int(length_of_data / 8))
    if output_file:
        write_to_txt(string_to_write, output_file)
    else:
        print("Decoded data from chunk of binary file")
        print("-------------------------------------------------------------------------------------------------------")
        print(string_to_write)
        print("-------------------------------------------------------------------------------------------------------")


def check_piece_of_data(piece):
    # check a piece of data
    checked_piece = ""
    global num_errors
    bit_array = arr.array('i', [])
    error_matrix = np.array([[1, 1, 0], [0, 1, 1], [1, 1, 1], [1, 0, 1],
                            [1, 0, 0], [0, 1, 0], [0, 0, 1]])
    parity_bit = int(piece[7:], 2)

    for char in piece[:-1]:
        bit_int = int(char, 2)
        bit_array.append(bit_int)

    vector_to_check = np.array(bit_array)

    # result vector = H * data vector
    result = control_matrix.dot(vector_to_check) % 2

    num_zeros = bit_array.count(0)
    calculated_parity_bit = fill_to_even(num_zeros)

    if (result == [0, 0, 0]).all():
        if calculated_parity_bit != parity_bit:
            checked_piece = piece[:-1] + str(calculated_parity_bit)
            num_errors = 1
        else:
            checked_piece = piece
            num_errors = 0
    else:
        if calculated_parity_bit == parity_bit:
            print("DOUBLE ERROR DETECTED")
            num_errors = 2
        else:
            index = index_to_repair(error_matrix, result)
            checked_piece = repair_at_index(piece, index)
            num_errors = 1
    return checked_piece


def repair_at_index(data, index):
    # repairs data at index
    list_string = list(data)
    if list_string[index] == "0":
        list_string[index] = "1"
    else:
        list_string[index] = "0"
    return "".join(list_string)


def index_to_repair(error_matrix, result):
    # returns index
    index = 0
    for i in range(0, len(error_matrix)):
        if (error_matrix[i] == result).all():
            index = i
            break
    return index


def get_data_without_hamming(array_data):
    # returns data without parity bits
    result_text = ""
    for item in array_data:
        result_text += item[:-4]
    return result_text


def bitstring_into_string(list_coded_string):
    # converts bitstring into string
    list_coded = re.findall('........', list_coded_string)
    result_string = ""
    for item in list_coded:
        result_string += chr(int(item, 2))
    return result_string


def bytes_to_bits(_bytes):
    # input bytes to bit/string in 8-bit format
    to_bits = ''.join(format(x, '08b') for x in _bytes)
    return to_bits


def check_arguments(input_args):
    # validates data and returns possible errors
    input_file = input_args.i
    mode = input_args.m
    if not os.path.exists(input_file):
        parser.error("The file %s does not exist!" % input_args.i)
    else:
        if mode == "k" and not input_file.endswith(".txt"):
            parser.error("The input file for Hamming coding must have an extension .txt")
        elif mode == "d" and not input_file.endswith(".bin"):
            parser.error("The input file for Hamming decoding must have an extension .bin")

    if input_args.o:
        output_file = input_args.o
        if mode == "k" and not output_file.endswith(".bin"):
            parser.error("The output file for Hamming coding must have an extension .bin.")
        elif mode == "d" and not output_file.endswith(".txt"):
            parser.error("The output file for Hamming decoding must have an extension .txt")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Give some parameters")
    parser.add_argument("m", choices=['k', 'd'], help="Mode of Coding (k = coding, d = decoding)")
    parser.add_argument("i", metavar="FILE", help="Input File (.txt/.bin)")
    parser.add_argument("o", metavar="FILE", nargs="?", default="", help="Output File (.bin/.txt)")
    args = parser.parse_args()
    check_arguments(args)
    main(args)
