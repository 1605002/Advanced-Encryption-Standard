import binascii
from BitVector import *

roundDix = {128:10, 192:12, 256:14}
byteDix = {128:16, 192:24, 256:32}

AES_modulus = BitVector(bitstring='100011011')
bzero = BitVector(hexstring="00")
btwo = BitVector(hexstring="02")

Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

InvSbox = (
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
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

Mixer = [
    [BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03")],
    [BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02")]
]

InvMixer = [
    [BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09")],
    [BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D")],
    [BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B")],
    [BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E")]
]

def getMatrixForm(byteArray):
    """Transforms "byteArray" to desired matrix form and returns it."""
    metrix = [] # A 2D list to contain the words of "byteArray" in column-major order
    length = len(byteArray)

    for k in range(4):
        row = [BitVector(hexstring=byteArray[i]) for i in range(k, length, 4)]
        metrix.append(row)

    return metrix

"""
    In the following functions,
    each of row, row1, row2 is a list with four BitVector objects representing a word.
"""

def subBytes(row):
    """Builds a new list by
    substituting each hex byte from "row" list with associated Sbox value and returns it.
    """
    return [BitVector(intVal=Sbox[bv.intValue()], size=8) for bv in row]

def subBytes2(matrix):
    """Does the same thing as subBytes() for a 2D list"""
    return [subBytes(row) for row in matrix]

def invSubBytes(row):
    """Builds a new list by
    substituting each hex byte from "row" list with associated InvSbox value and returns it.
    """
    return [BitVector(intVal=InvSbox[bv.intValue()], size=8) for bv in row]

def invSubBytes2(matrix):
    """Does the same thing as invSubBytes() for a 2D list"""
    return [invSubBytes(row) for row in matrix]

def jog(row1, row2):
    """Builds a new list by xoring matching hex bytes from "row1" and "row2" lists and returns it."""
    return [a^b for a, b in zip(row1, row2)]

def jog2(matrix1, matrix2):
    """Builds a new 2D list by xoring matching hex bytes from "matrix1" and "matrix2" lists and returns it."""
    return [jog(row1, row2) for row1, row2 in zip(matrix1, matrix2)]

def jogList(row):

    result = bzero
    for entry in row:
        result = result^entry

    return result

def left_shift(row, koybar):
    """Builds a new list by left shifting "row" by "koybar" and returns it."""
    nrow = row[:]
    for i in range(koybar):
        nrow.append(nrow.pop(0))

    return nrow

def left_shift2(matrix):
    """Builds a new 2D list by left shifting each row by AES rules"""
    return [left_shift(matrix[i], i) for i in range(4)]

def right_shift(row, koybar):
    """Builds a new list by right shifting "row" by "koybar" and returns it."""
    nrow = row[:]
    for i in range(koybar):
        nrow.insert(0, nrow.pop())

    return nrow

def right_shift2(matrix):
    """Builds a new 2D list by right shifting each row by AES rules"""
    return [right_shift(matrix[i], i) for i in range(4)]

def g(row, rc):
    """Calucales g(row) with round constant "rc" and returns it."""
    nrow = left_shift(row, 1) # Circular left shift
    nrow = subBytes(nrow) # Substitute bytes
    nrow = jog(nrow, [rc, bzero, bzero, bzero]) # Add round key

    return nrow


def multiply(matrix1, matrix2):
    return [[jogList([a.gf_multiply_modular(b, AES_modulus, 8) for a, b in zip(row, col)]) \
        for col in zip(*matrix2)] for row in matrix1]

def printMatrix(matrix):
    for row in matrix:
        for entry in row:
            print(entry.get_bitvector_in_hex(), end=" ")
        print()
    print()

def scheduleKey(key):
    """
        key = a list of string where each element is a two character hex string

        This function expands one key to nro+1 keys and returns it
        nro = number_of rounds depending on the type of AES which is determined by the size of key
        Each of the nro+1 keys are stored as a 2D list and the whole thing is stored as a 3D list.
    """

    length = len(key)
    aestype = length*8
    nro = roundDix[aestype]
    cols = int(length/4) # Number of words the key contains depending on the type of AES

    scheduledKeys = [] # A 3D list to contain all the expanded keys
    initialKey = getMatrixForm(key) # A 2D list to contain the bytes of the key in column-major order

    scheduledKeys.append(initialKey)

    rc = BitVector(hexstring="01") # Round constant

    for roundNo in range(1, nro+1):
        lst = g([scheduledKeys[roundNo-1][i][cols-1] for i in range(4)], rc) # g(the last word of last roumd)
        
        thisRoundKey = [] # A 2D list to contain this round's key

        for j in range(cols):
            prv = [scheduledKeys[roundNo-1][i][j] for i in range(4)] # Matching column word from last round
            newWord = jog(prv, lst) # Next word
            thisRoundKey.append(newWord)
            lst = newWord

        thisRoundKey = list(map(list, zip(*thisRoundKey))) # Trasnposing the row-major list
        scheduledKeys.append(thisRoundKey)
        
        rc = btwo.gf_multiply_modular(rc, AES_modulus, 8) # round_constant = 2 * round_constant (with MOD)

    """
    for roundkey in scheduledKeys:
        printMatrix(roundkey)
    """

    return scheduledKeys

def encryptBlock(block, expandedKeys, nro):
    
    cypher = jog2(getMatrixForm(block), expandedKeys[0])    

    for i in range(1, nro+1):
        cypher = subBytes2(cypher)
        cypher = left_shift2(cypher)
        if(i < nro): cypher = multiply(Mixer, cypher)
        cypher = jog2(cypher, expandedKeys[i])

    cypherBlock = [entry.get_bitvector_in_hex() for col in zip(*cypher) for entry in col]
    return cypherBlock

def encryptFull(line, key, nro):
    expandedKeys = scheduleKey(key)
    length = len(line)
    sz = len(key)
    
    result = []
    for i in range(0, length, sz):
        result.extend(encryptBlock(line[i:i+sz], expandedKeys, nro))

    return result

def decryptBlock(block, expandedKeys, nro):
    
    plainText = jog2(getMatrixForm(block), expandedKeys[0])

    for i in range(1, nro+1):
        plainText = invSubBytes2(plainText)
        plainText = right_shift2(plainText)
        plainText = jog2(plainText, expandedKeys[i])
        if(i < nro): plainText = multiply(InvMixer, plainText)

    plainTextBlock = [entry.get_bitvector_in_hex() for col in zip(*plainText) for entry in col]
    return plainTextBlock

def decryptFull(line, key, nro):
    expandedKeys = scheduleKey(key)
    expandedKeys.reverse()

    length = len(line)
    sz = len(key)

    result = []
    for i in range(0, length, sz):
        result.extend(decryptBlock(line[i:i+sz], expandedKeys, nro))

    return result

def hexStringToArray(senHex):
    length = len(senHex)
    senHex = [senHex[i:i+2] for i in range(0, length, 2)]

    return senHex

def stringToHex(sentence):
    return hexStringToArray(sentence.encode().hex())

def hexToString(senHex): return bytes.fromhex("".join(senHex)).decode("latin-1", errors="ignore")

def takeInput():
    isFile = bool(int(input("Enter 1 for text or 2 for file: "))-1)
    title = input("Enter " + ("file name" if isFile else "text") + ": ")
    key = input("Enter key: ")

    return title, isFile, key

def aes(aesType, title, isFile, key):
    print("\nAES-" + str(aesType) + ":\n")

    titleHex = stringToHex(title)
    if isFile:
        with open(title, 'rb') as f:
            titleHex = f.read().hex()
            titleHex = hexStringToArray(titleHex)

    keyHex = stringToHex(key)
    titleLen, keyLen = len(titleHex), len(keyHex)

    sz = int(aesType/8)
    nro = roundDix[aesType]

    while keyLen > sz:
        keyHex.pop()
        keyLen -= 1
    while keyLen < sz:
        keyHex.append("30")
        keyLen += 1

    extra = 0
    while((titleLen+extra)%sz != 0):
        titleHex.append("00")
        extra += 1

    print("Plain text/file contents (in hex): " + "".join(titleHex))
    print("Key (in hex): " + "".join(keyHex))

    cypherHex = encryptFull(titleHex, keyHex, nro)
    print("Cypher text (in hex): " + "".join(cypherHex))
    print("Cypher text (in ASCII): " + hexToString(cypherHex))

    
    detitleHex = decryptFull(cypherHex, keyHex, nro)
    print("Deciphered text/file contents (in hex): " + "".join(detitleHex))

    while extra > 0:
        detitleHex.pop()
        extra -= 1

    if(isFile):
        # Need to create a new file
        with open("decrypted_" + title, 'wb') as f:
            f.write(binascii.unhexlify("".join(detitleHex)))

        print("New decrypted_" + title + " file has been created.")
    else:
        print("Deciphered text (in ASCII): " + hexToString(detitleHex))

title, isFile, key = takeInput()

aes(128, title, isFile, key)
#aes(192, title, isFile, key)
#aes(256, title, isFile, key)