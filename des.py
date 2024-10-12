import sys


PC1 = [57,  49,  41,  33,  25,  17,   9,
        1,  58,  50,  42,  34,  26,  18,
       10,   2,  59,  51,  43,  35,  27,
       19,  11,   3,  60,  52,  44,  36,
       63,  55,  47,  39,  31,  23,  15,
        7,  62,  54,  46,  38,  30,  22,
       14,   6,  61,  53,  45,  37,  29,
       21,  13,   5,  28,  20,  12,   4]

PC2 = [14,  17,  11,  24,   1,   5,
       3,   28,  15,   6,  21,  10,
       23,  19,  12,   4,  26,   8,
       16,   7,  27,  20,  13,   2,
       41,  52,  31,  37,  47,  55,
       30,  40,  51,  45,  33,  48,
       44,  49,  39,  56,  34,  53,
       46,  42,  50,  36,  29,  32]

LSHIFT_MAP = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

IP = [58,  50,  42,  34,  26,  18,  10,   2,
      60,  52,  44,  36,  28,  20,  12,   4,
      62,  54,  46,  38,  30,  22,  14,   6,
      64,  56,  48,  40,  32,  24,  16,   8,
      57,  49,  41,  33,  25,  17,   9,   1,
      59,  51,  43,  35,  27,  19,  11,   3,
      61,  53,  45,  37,  29,  21,  13,   5,
      63,  55,  47,  39,  31,  23,  15,   7]

E = [32,   1,   2,   3,   4,   5,
      4,   5,   6,   7,   8,   9,
      8,   9,  10,  11,  12,  13,
     12,  13,  14,  15,  16,  17,
     16,  17,  18,  19,  20,  21,
     20,  21,  22,  23,  24,  25,
     24,  25,  26,  27,  28,  29,
     28,  29,  30,  31,  32,   1]

SBOXES = {0:
            [[14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7],
             [ 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8],
             [ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],
             [15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13]],
          1:
            [[15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10],
             [ 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5],
             [ 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15],
             [13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9]],
          2:
            [[10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8],
             [13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1],
             [13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7],
             [ 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12]],
          3:
            [[ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15],
             [13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9],
             [10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4],
             [ 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14]],
          4:
            [[ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9],
             [14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6],
             [ 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14],
             [11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3]],
          5:
            [[12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11],
             [10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8],
             [ 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6],
             [ 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13]],
          6:
            [[ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1],
             [13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6],
             [ 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2],
             [ 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12]],
          7:
            [[13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7],
             [ 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2],
             [ 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8],
             [ 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11]]}

P = [16,   7,  20,  21,
     29,  12,  28,  17,
      1,  15,  23,  26,
      5,  18,  31,  10,
      2,   8,  24,  14,
     32,  27,   3,   9,
     19,  13,  30,   6,
     22,  11,   4,  25]

IP_INVERSE = [40,   8,  48,  16,  56,  24,  64,  32,
              39,   7,  47,  15,  55,  23,  63,  31,
              38,   6,  46,  14,  54,  22,  62,  30,
              37,   5,  45,  13,  53,  21,  61,  29,
              36,   4,  44,  12,  52,  20,  60,  28,
              35,   3,  43,  11,  51,  19,  59,  27,
              34,   2,  42,  10,  50,  18,  58,  26,
              33,   1,  41,   9,  49,  17,  57,  25]


def hex_to_64binary(hexstr):
    try:
        int64 = int(hexstr, 16)
    except ValueError:
        raise ValueError('ERROR: can not convert %s to base 16.' % hexstr)

    bin64 = str(bin(int64))[2:].rjust(64, '0')

    return bin64


def binary_to_hex(binstr):
    hexstr = []

    for i in range(0, len(binstr), 4):
        total = 0
        binstr_rev = [x for x in reversed(binstr[i:i+4])]
        for j in range(4):
            total += (2**j) * int(binstr_rev[j])
        hexstr.append('%X' % total)

    return ''.join(hexstr)


def string_chunker(label, value, break_at):
    chunks = []
    for i in range(0, len(value), break_at):  
        chunks.append(value[i:i + break_at])
    return ' '.join(chunks)



def lshift(c, d, iteration):
    for i in range(LSHIFT_MAP[iteration]):  
        c = c[1:] + c[0]  # Shift left on c
        d = d[1:] + d[0]  # Shift left on d
    return c, d



def permutate(permutation, in_bits, out_bits_wide):
    out_bits = [-1] * out_bits_wide
    for i in range(len(permutation)):  
        in_bits_i = permutation[i] - 1
        out_bits[i] = in_bits[in_bits_i]

    return ''.join(map(str, out_bits))


def xor(bits1, bits2):
    return ''.join('1' if bits1[i] != bits2[i] else '0' for i in range(len(bits1)))  

def message_to_hex(msg):
    hexstr = []

    for c in msg:
        hexstr.append('%X' % ord(c))

    return ''.join(hexstr)


def get_hexwords(msg):
    hexwords = []

    for i in range(0, len(msg), 8):  
        msg_block = msg[i:i+8]
        m = message_to_hex(msg_block)
        hexwords.append(m)

    last = hexwords[-1]
    hexwords[-1] += ''.join(['0'] * (16 - len(last)))

    return hexwords



def encrypt(key, msg):
    encrypted_msg = []

    for hexword in get_hexwords(msg):
        encrypted_msg.append(encrypt_hexword(key, hexword))

    return ''.join(encrypted_msg)


def encrypt_hexword(key, hexword):
    k = hex_to_64binary(key)
    m = hex_to_64binary(hexword)
    
    ip = permutate(IP, m, 64)

    middle = len(ip) // 2  
    l = ip[:middle]
    r = ip[middle:]

    cd = permutate(PC1, k, 56)
    middle = len(cd) // 2
    c = cd[:middle]
    d = cd[middle:]

    for round_i in range(16):  

        (c, d) = lshift(c, d, round_i)

        k = permutate(PC2, c + d, 48)
        e = permutate(E, r, 48)

        x = xor(k, e)

        s = []
        for n in range(len(x) // 6):  
            start = 6 * n
            end = (6 * n) + 6
            b = x[start:end]
            i = int(b[0]) * 2**1 + int(b[-1]) * 2**0
            j = (int(b[1]) * 2**3 + int(b[2]) * 2**2 + int(b[3]) * 2**1 + int(b[4]) * 2**0)
            s.append(str(bin(SBOXES[n][i][j]))[2:].rjust(4, '0'))
        s = ''.join(s)

        f = permutate(P, s, 32)

        l_prev = l

        l = r

        r = xor(l_prev, f)

    rl = f'{r}{l}'  

    encrypted_msg = permutate(IP_INVERSE, rl, 64)

    bin2hex = binary_to_hex(encrypted_msg)

    return bin2hex


def decrypt(key, ciphertext):
    decrypted_msg = []

    for hexword in [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]:
        decrypted_msg.append(decrypt_hexword(key, hexword))

    return ''.join(decrypted_msg)


def decrypt_hexword(key, hexword):
    k = hex_to_64binary(key)
    
    m = hex_to_64binary(hexword)

    ip = permutate(IP, m, 64)

    middle = len(ip) // 2
    l = ip[:middle]
    r = ip[middle:]

    cd = permutate(PC1, k, 56)
    middle = len(cd) // 2
    c = cd[:middle]
    d = cd[middle:]

    subkeys = []

    for round_i in range(16):
        (c, d) = lshift(c, d, round_i)
        subkey = permutate(PC2, c + d, 48)
        subkeys.append(subkey)

    for round_i in reversed(range(16)):
        k = subkeys[round_i]
        e = permutate(E, r, 48)
        x = xor(k, e)

        s = []
        for n in range(len(x) // 6):
            start = 6 * n
            end = (6 * n) + 6
            b = x[start:end]
            i = int(b[0]) * 2**1 + int(b[-1]) * 2**0
            j = int(b[1:5], 2)
            s.append(str(bin(SBOXES[n][i][j]))[2:].rjust(4, '0'))

        s = ''.join(s)
        f = permutate(P, s, 32)

        new_r = xor(l, f)
        l = r
        r = new_r

    final_permutation = permutate(IP_INVERSE, r + l, 64)

    return binary_to_hex(final_permutation)



def run():
    mode = input("Digite 'e' para criptografar ou 'd' para descriptografar: ").lower()
    
    key = input("Digite a chave (16 caracteres): ").upper()
    if len(key) != 16:
        print("A chave precisa ter 16 caracteres.")
        return

    key = key.encode('utf-8').hex().upper()

    if mode == 'e':
        msg = input("Digite a mensagem: ")
        print('key:', key)
        print('msg:', msg)

        if len(key) != 32:  
            print('ERROR: KEY needs to be 32 characters after conversion to hexadecimal.')
            return

        enc = encrypt(key, msg)  
        print(string_chunker('Mensagem criptografada:', enc, 16))

    elif mode == 'd':
        msg = input("Digite a mensagem: ")
        print('key:', key)
        print('msg:', msg)

        msg = msg.replace(" ", "")  
        try:
            dec = decrypt(key, msg)  
            decoded_message = bytes.fromhex(dec).decode('utf-8', errors='ignore')
            print('Mensagem descriptografada:', decoded_message)
        except ValueError as e:
            print(f"Erro ao converter a mensagem descriptografada: {e}")
    else:
        print("Opção inválida. Digite 'e' para criptografar ou 'd' para descriptografar.")

if __name__ == '__main__':
    run()
