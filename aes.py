import hashlib


SBOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]


INV_SBOX = [
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
    ]


RCON = [
        0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x00, 0x00,
        0x1b, 0x00, 0x00, 0x00,
        0x36, 0x00, 0x00, 0x00
    ]

def bytes_from_file(filename):
    file = open(filename, 'rb')
    bytes = bytearray(file.read())
    file.close()
    return bytes


def bytes_to_file(filename, bytes):
    file = open(filename, 'wb')
    file.write(bytes)
    file.close()


def extended_to(bytes, block_size):
    end = block_size - len(bytes) % block_size
    if end < 16:
        print('extended_to() added {0} bytes'.format(end))
        end = bytearray(end)
        end[0] = 0b1000_0000
        bytes += end
    return bytes


def reduce_end(bytes):
    for i in range(1, len(bytes) + 1):
        if bytes[-i] == 0x00:
            continue
        if bytes[-i] == 0x80:
            return bytes[:-i]
        return bytes


def split_bytes_to_states(bytes, Nb):
    states = []
    r, c = 0, 0
    for b in bytes:
        if r == 0 and c == 0:
            state = []
            for i in range(4):
                state.append([0] * Nb)
        state[r][c] = b
        r += 1
        if r >= 4:
            r = 0
            c += 1
        if c >= Nb:
            states.append(state)
            c = 0
    print('split_bytes_to_states() split to {0} states'.format(len(states)))
    return states


def states_to_bytes(states):
    bytes = bytearray()
    for s in states:
        for x in range(len(s[0])):
            for y in range(len(s)):
                bytes.append(s[y][x])
    return bytes


def sub_bytes(state):
    for i in range(4):
        for j in range(len(state[0])):
            state[i][j] = SBOX[state[i][j]]
    return state


def inv_sub_bytes(state):
    for i in range(4):
        for j in range(len(state[0])):
            state[i][j] = INV_SBOX[state[i][j]]
    return state


def shift_rows(state):
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]
    return state


def inv_shift_rows(state):
    state[1] = state[1][3:] + state[1][:3]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][1:] + state[3][:1]
    return state


def mix_columns(state):

    def mul02(x):
        if x < 0x80:
            return (x << 1) % 0x100
        return ((x << 1) ^ 0x1b) % 0x100

    def mul03(x):
        return mul02(x) ^ x

    for i in range(len(state[0])):
        s0 = mul02(state[0][i]) ^ mul03(state[1][i]) ^ state[2][i] ^ state[3][i]
        s1 = state[0][i] ^ mul02(state[1][i]) ^ mul03(state[2][i]) ^ state[3][i]
        s2 = state[0][i] ^ state[1][i] ^ mul02(state[2][i]) ^ mul03(state[3][i])
        s3 = mul03(state[0][i]) ^ state[1][i] ^ state[2][i] ^ mul02(state[3][i])

        state[0][i] = s0
        state[1][i] = s1
        state[2][i] = s2
        state[3][i] = s3

    return state


def inv_mix_columns(state):

    def mul02(x):
        if x < 0x80:
            return x << 1
        return ((x << 1) ^ 0x1b) % 0x100

    def mul09(x):
        return mul02(mul02(mul02(x))) ^ x

    def mul0b(x):
        return mul02(mul02(mul02(x))) ^ mul02(x) ^ x

    def mul0d(x):
        return mul02(mul02(mul02(x))) ^ mul02(mul02(x)) ^ x

    def mul0e(x):
        return mul02(mul02(mul02(x))) ^ mul02(mul02(x)) ^ mul02(x)

    for i in range(len(state[0])):
        s0 = mul0e(state[0][i]) ^ mul0b(state[1][i]) ^ mul0d(state[2][i]) ^ mul09(state[3][i])
        s1 = mul09(state[0][i]) ^ mul0e(state[1][i]) ^ mul0b(state[2][i]) ^ mul0d(state[3][i])
        s2 = mul0d(state[0][i]) ^ mul09(state[1][i]) ^ mul0e(state[2][i]) ^ mul0b(state[3][i])
        s3 = mul0b(state[0][i]) ^ mul0d(state[1][i]) ^ mul09(state[2][i]) ^ mul0e(state[3][i])

        state[0][i] = s0
        state[1][i] = s1
        state[2][i] = s2
        state[3][i] = s3

    return state


def key_expansion(key, Nb, Nr):

    # формирование пустого массива столбцов
    keySchedule = []
    for i in range(Nb * (Nr + 1)):
        keySchedule.append([None] * 4)

    # заполнение первого state
    for i in range(len(key)):
        keySchedule[int(i / 4)][i % 4] = key[i]

    # дозаполнение keyShaldure
    for i in range(Nb, Nb * (Nr + 1)):
        if i % 4 == 0:
            keySchedule[i] = [keySchedule[i - 1][(j + 1) % 4] for j in range(4)]
            keySchedule[i] = [keySchedule[i][j] ^ keySchedule[i - Nb][j] for j in range(4)]
            keySchedule[i] = [keySchedule[i][j] ^ RCON[4 * int(i / Nb) + j] for j in range(4)]
        else:
            keySchedule[i] = [keySchedule[i - 1][j] ^ keySchedule[i - Nb][j] for j in range(4)]

    # преобразование массива столбцов в массив state
    tmp = []
    for i in range(Nr + 1):
        tmp.append([])
        for j in range(4):
            tmp[-1].append([None] * Nb)
    for x in range(len(keySchedule)):
        for y in range(4):
            tmp[int(x / Nb)][y][x % Nb] = keySchedule[x][y]

    return tmp


def add_round_key(state, roundKey):
    for y in range(len(state)):
        for x in range(len(state[y])):
            state[y][x] ^= roundKey[y][x]
    return state


# TODO: Nk == Nb ?
def encrypt_file(input_file, output_file, key, Nb=4, Nr=10):
    print('Encrypting file...\t', input_file, ' -> ', output_file, ',\tkey=', key.hex(),
          ', Nb=', Nb, ', Nr=', Nr)

    # чтение байт файлов и сохранение кеша для возврата функцией
    bytes = bytes_from_file(input_file)
    input_hash = hashlib.md5(bytes).digest()

    # дозаполнение масива байт до длины блока и разбиение
    bytes = extended_to(bytes, 4 * Nb)
    states_list = split_bytes_to_states(bytes, Nb)

    # генерация ключей
    keySchedule = key_expansion(key, Nb, Nr)

    # шифрование
    for state in states_list:

        state = add_round_key(state, keySchedule[0])

        for r in range(1, Nr):

            state = sub_bytes(state)
            state = shift_rows(state)
            state = mix_columns(state)
            state = add_round_key(state, keySchedule[r])

        state = sub_bytes(state)
        state = shift_rows(state)
        state = add_round_key(state, keySchedule[-1])

    bytes = states_to_bytes(states_list)

    bytes_to_file(output_file, bytes)
    output_hash = hashlib.md5(bytes).digest()

    return input_hash, output_hash


def decrypt_file(input_file, output_file, key, Nb=4, Nr=10):
    print('Decrypting file...\t', input_file, ' -> ', output_file, ',\tkey=', key.hex(),
          ', Nb=', Nb, ', Nr=', Nr)

    bytes = bytes_from_file(input_file)
    input_hash = hashlib.md5(bytes).digest()

    bytes = extended_to(bytes, 4 * Nb)
    states_list = split_bytes_to_states(bytes, Nb)

    keySchedule = key_expansion(key, Nb, Nr)

    for state in states_list:

        state = add_round_key(state, keySchedule[-1])

        for r in range(Nr - 1, 0, -1):
            state = inv_shift_rows(state)
            state = inv_sub_bytes(state)
            state = add_round_key(state, keySchedule[r])
            state = inv_mix_columns(state)

        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, keySchedule[0])

    bytes = states_to_bytes(states_list)
    bytes = reduce_end(bytes)

    bytes_to_file(output_file, bytes)
    output_hash = hashlib.md5(bytes).digest()

    return input_hash, output_hash



if __name__ == '__main__':

    key = 'fj49xfnii9__D4fk'
    input_file_name = 'image2.jpg'
    crypted_file_name = 'crypt.aes'
    output_file_name = 'output_image.jpg'

    print('key: ', key)
    key = hashlib.md5(key.encode('utf-8')).digest()

    input_hash, crypted_hash = encrypt_file(input_file_name, crypted_file_name, key)
    print(input_hash.hex(), ' -> ', crypted_hash.hex())

    crypted_hash, output_hash = decrypt_file(crypted_file_name, output_file_name, key)
    print(crypted_hash.hex(), ' -> ', output_hash.hex())

    print('Result: ', end='')
    if input_hash == output_hash:
        print('OK')
    else:
        print('Failed')
