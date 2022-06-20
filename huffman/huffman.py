import argparse
import os.path
import queue
import json
import filecmp
import difflib


class HuffmanNode(object):
    def __init__(self, left=None, right=None):
        self.left = left
        self.right = right

    def children(self):
        return ((self.left, self.right))

    def __lt__(self, other):
        return 0

    def __gt__(self, other):
        return 1


def main(input_args):
    if input_args.m == "k":
        with open(input_args.i, "r") as first_file:
            for piece in read_in_chunks(first_file):
                bytes_to_write = compress(piece, input_args.o)
                if input_args.o:
                    with open(input_args.o, "ab") as second_file:
                        second_file.write(bytes_to_write)
                        second_file.close()
            first_file.close()

    elif args.m == "d":
        with open(input_args.i, "rb") as first_file:
            while True:
                # read 2 bytes => length of chunk in bytes
                length_of_piece_in_bin = first_file.read(2)
                if not length_of_piece_in_bin:
                    break
                if len(length_of_piece_in_bin) == 1:
                    last_byte = length_of_piece_in_bin
                    last_byte_to_bits = bytes_to_bits(last_byte)
                    last_byte_int = int(last_byte_to_bits, 2)
                    char_in_string = last_byte_int.to_bytes((last_byte_int.bit_length() + 7) // 8, 'big').decode()
                    if input_args.o:
                        write_to_txt(char_in_string, input_args.o)
                    else:
                        print(char_in_string)
                else:
                    # length of piece from bytes to int
                    length_of_piece_as_bits = bytes_to_bits(length_of_piece_in_bin)
                    length_of_piece_int = int(length_of_piece_as_bits, 2)

                    # read 2 bytes => length of dictionary in bytes
                    length_dict = first_file.read(2)
                    length_dict_as_bits = bytes_to_bits(length_dict)
                    length_dict_int = int(length_dict_as_bits, 2)
                    length_of_piece_int -= len(length_dict)

                    # read bytes for dictionary
                    binary_code_dict = first_file.read(length_dict_int)
                    code_dict_to_string = binary_code_dict.decode("utf-8")
                    code_dict = json.loads(code_dict_to_string)
                    length_of_piece_int -= len(binary_code_dict)

                    # read 1 byte for padded bits
                    binary_padded_info = first_file.read(1)
                    padded_info = bytes_to_bits(binary_padded_info)
                    padded_bits = int(padded_info, 2)
                    length_of_piece_int -= len(binary_padded_info)

                    # read remaining bytes in chunk
                    bytes_remaining = first_file.read(length_of_piece_int)
                    remaining_bits = bytes_to_bits(bytes_remaining)
                    decoded = decoded_text(remaining_bits[:-padded_bits], code_dict)
                    if input_args.o:
                        write_to_txt(decoded, input_args.o)
                    else:
                        print("Code dict for chunk")
                        print(code_dict)
                        print("-------------------")
        first_file.close()


def write_to_txt(decoded, output):
    # writes decoded data to txt file
    with open(output, "a") as output_file:
        output_file.write(decoded)
    output_file.close()


def bytes_to_bits(_bytes):
    # input bytes to bit/string in 8-bit format
    to_bits = ''.join(format(x, '08b') for x in _bytes)
    return to_bits


def compress(piece_of_text, input_args):
    # returns bytearray to write
    bytes_to_write = bytearray()

    # check length of the last block of data
    if len(piece_of_text) == 1:
        # if the last byte has length 1, converts his ASCII value to binary
        if ord(piece_of_text) > 127:
            piece_of_text = "?"
        piece_of_text_bits = "{0:08b}".format(ord(piece_of_text))
        bytes_to_write = _to_bytes(piece_of_text_bits)
    else:
        # Huffman compression
        # list of frequencies of each character in chunk
        table_frequencies = make_frequency_dict(piece_of_text)

        # create Huffman Tree and return "top node"
        top_node = create_tree(table_frequencies)

        # make codes for characters
        code = walk_tree(top_node)

        # create code dictionary
        code_dict = make_code_dict(table_frequencies, code)

        # convert code dictionary to bitstring
        binary_code_dict = json.dumps(code_dict)
        code_dict_in_binstring = string2bin(binary_code_dict)

        # encode input data using code dictionary
        encoded = encoded_text(piece_of_text, code_dict)

        # just a reference to pure encoded data without information bytes
        pure_encoded = encoded

        # fill zeros to 8k block
        extra_padding = 8 - len(encoded) % 8
        padded_info = "{0:08b}".format(extra_padding)
        for i in range(extra_padding):
            encoded = encoded + "0"

        # length of code dictionary in full size bits
        length_code_dict = int(len(code_dict_in_binstring) / 8)
        length_code_dict = "{0:b}".format(length_code_dict)
        length_code_dict = fill_zeros(length_code_dict)

        # add information bytes to encoded data
        encoded = length_code_dict + code_dict_in_binstring + padded_info + encoded

        # 2 information bytes about size of encoded chunk in bytes
        to_read = int(len(encoded) / 8)
        temp_to_read = "{0:b}".format(to_read)
        temp_to_read = fill_zeros(temp_to_read)

        # 2 information bytes added to encoded data to write
        encoded = temp_to_read + encoded

        # encoded data to bytes
        bytes_to_write = _to_bytes(encoded)
        if not input_args:
            print("Code dictionary for chunk of data")
            print(code_dict)
            print("----------------")
            print("Pure encoded data")
            print(pure_encoded)
            print("----------------")
    return bytes_to_write


def fill_zeros(input_target):
    # fill zeros to data
    if len(input_target) != 16:
        for zero in range(16 - len(input_target)):
            input_target = "0" + input_target
    return input_target


def string2bin(string):
    # returns string bin
    return "".join(f"{ord(i):08b}" for i in string)


def make_code_dict(table_frequencies, code):
    # returns code dictionary for each chunk of input data
    code_dict = {}
    for i in sorted(table_frequencies, reverse=True):
        code_dict[i[1]] = code[i[1]]
    return code_dict


def read_in_chunks(file, chunk_size=8192):
    # reads from txt file with specific chunk_size
    while True:
        data = file.read(chunk_size)
        if not data:
            break
        yield data


def coded_tree_in_binary_string(list_nodes):
    # tree to binstring
    coded_tree = ""
    for char in list_nodes:
        if char == "0":
            coded_tree = coded_tree + "0"
        elif char == "1":
            coded_tree = coded_tree + "1"
        else:
            char_to_bin = '{:08b}'.format(ord(char))
            coded_tree = coded_tree + char_to_bin
    return coded_tree


def _to_bytes(data):
    # bitstring to bytes
    byte_array = bytearray()
    for i in range(0, len(data), 8):
        byte_array.append(int(data[i:i+8], 2))
    return bytes(byte_array)


def text_to_bits(text, encoding='utf-8', errors='surrogatepass'):
    # text to bits
    bits = bin(int.from_bytes(text.encode(encoding, errors), 'big'))[2:]
    return bits.zfill(8 * ((len(bits) + 7) // 8))


def encoded_text(text, code_dict):
    # codes data using code dictionary
    text_encoded = ""
    for character in text:
        if ord(character) > 127:
            character = "?"
            print("AA")
        text_encoded += code_dict[character]
    return text_encoded


# unused function, was prepared for better storing a tree in binary file
def preorder(node, list_of_chars):
    if isinstance(node[1], str):
        list_of_chars.append("1")
        list_of_chars.append(node[1])
    else:
        list_of_chars.append("0")
        preorder(node[1].left, list_of_chars)
        preorder(node[1].right, list_of_chars)
    return list_of_chars


def walk_tree(node, prefix="", code={}):
    # walks a created tree and returns codes
    if isinstance(node[1].left[1], HuffmanNode):
        walk_tree(node[1].left, prefix + "0", code)
    else:
        code[node[1].left[1]] = prefix + "0"
    if isinstance(node[1].right[1], HuffmanNode):
        walk_tree(node[1].right, prefix + "1", code)
    else:
        code[node[1].right[1]] = prefix + "1"
    return (code)


def make_frequency_dict(text):
    # returns list of frequencies of each character, characters with ASCII code bigger than 127 are replaced by "?"
    frequency = {}
    for character in text:
        if ord(character) > 127:
            character = "?"
        if not character in frequency:
            frequency[character] = 0
        frequency[character] += 1
    frequencies_in_list = []
    for key in frequency:
        frequencies_in_list.append(tuple((frequency[key], key)))
    return frequencies_in_list


def create_tree(frequencies):
    # creates tree and returns top node
    p = queue.PriorityQueue()
    for value in frequencies:
        p.put(value)
    while p.qsize() > 1:
        l, r = p.get(), p.get()
        node = HuffmanNode(l, r)
        p.put((l[0]+r[0], node))
    return p.get()


def decoded_text(encoded, code_dict):
    # decode encoded text using dictionary of codes
    decoded = ""
    while encoded:
        for key in code_dict:
            if encoded.startswith(code_dict[key]):
                decoded += key
                encoded = encoded[len(code_dict[key]):]
    return decoded


def check_arguments(input_args):
    # validates data and return possible errors
    input_file = input_args.i
    mode = input_args.m
    if not os.path.exists(input_file):
        parser.error("The file %s does not exist!" % input_args.i)
    else:
        if mode == "k" and not input_file.endswith(".txt"):
            parser.error("The input file for Huffman coding must have an extension .txt")
        elif mode == "d" and not input_file.endswith(".bin"):
            parser.error("The input file for Huffman decoding must have an extension .bin")

    if input_args.o:
        output_file = input_args.o
        if mode == "k" and not output_file.endswith(".bin"):
            parser.error("The output file for Huffman coding must have an extension .bin.")
        elif mode == "d" and not output_file.endswith(".txt"):
            parser.error("The output file for Huffman decoding must have an extension .txt")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Give some parameters")
    parser.add_argument("m", choices=['k', 'd'], help="Mode of Coding (k = coding, d = decoding)")
    parser.add_argument("i", metavar="FILE", help="Input File (.txt/.bin)")
    parser.add_argument("o", metavar="FILE", nargs="?", default="", help="Output File (.bin/.txt)")
    args = parser.parse_args()
    check_arguments(args)
    main(args)
