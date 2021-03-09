import binascii
import time
from BitVector import *

roundDix = {128:10, 192:12, 256:14} # {aesType: number of rounds}

AES_modulus = BitVector(bitstring='100011011') # Used in gf_multiply_modular()
bzero = BitVector(hexstring="00")
btwo = BitVector(hexstring="02")
bsthree = BitVector(hexstring="63")

Sbox = [0] * 256
InvSbox = [0] * 256

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
"""
A table to speed up bitvector multiplication.
The Mixer and InvMixer matrix only contains eight distinct bitVectors.
So we can precalculate their products with all 256 bitvectors.
This will allow us to avoid multiplication in encryption or decryption process.
"""
gunTable = [] 

def preCalc():
    lagbe = {0, 1, 2, 3, 9, 11, 13, 14} # All the values present in Mixer and InvMixer

    for i in range(16):
        newRow = []
        if i in lagbe:
            for j in range(256):
                a = BitVector(intVal=i, size=8)
                b = BitVector(intVal=j, size=8)

                newRow.append(a.gf_multiply_modular(b, AES_modulus, 8))

        gunTable.append(newRow)

    # gunTable[i][j] now contains i*j (in 2^8 GF field)

def preCalcSBox():
    """
    SBox[i] = b ^ b<<1 ^ b<<2 ^ b<<3 ^ b<<4 ^ 63(hex)
    b is the multiplicative inverse of i
    b can be found using gf_MI()
    InvSBox[SBox[i]] = i
    """

    for i in range(0, 256):
        cur = BitVector(intVal=i, size=8)
        cur = cur.gf_MI(AES_modulus, 8) if i > 0 else bzero # 0 doesn't have a MI

        tmpa = BitVector(intVal=cur.intValue(), size=8)
        tmpb = BitVector(intVal=cur.intValue(), size=8)
        tmpc = BitVector(intVal=cur.intValue(), size=8)
        tmpd = BitVector(intVal=cur.intValue(), size=8)
        tmpe = BitVector(intVal=cur.intValue(), size=8)

        """
        For some peculiar reason, bitVectors do the circular shift in place.
        tmpb << 1 returns the previous tmpb, but it will change tmpb to tmpb << 1 in place.
        """
        tmpb << 1 
        tmpc << 2
        tmpd << 3
        tmpe << 4

        nw = (tmpa^tmpb^tmpc^tmpd^tmpe^bsthree)
        
        Sbox[i] = nw.intValue()
        InvSbox[nw.intValue()] = i

def getMatrixForm(byteArray):
    """
    Transforms "byteArray" to desired matrix form and returns it.
    ["00", "01", "02, "05", "00", "01", "02, "05", "10", "11", "12, "51", "60", "A5", "BC, "00"] ->
    [["00", "01, "02", "05"],
     ["00", "01, "02", "05"],
     ["10", "11, "12", "51"],
     ["60", "A5", "BC", "00"]]
    """
    metrix = [] # A 2D list to contain the words of "byteArray" in column-major order
    length = len(byteArray)

    for k in range(4):
        row = [BitVector(hexstring=byteArray[i]) for i in range(k, length, 4)]
        metrix.append(row)

    return metrix

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
    """Calculates the xor of all elements in "row" list and returns it."""
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
    """Builds a new 2D list by left shifting each row of "matrix" by AES rules"""
    return [left_shift(matrix[i], i) for i in range(4)]

def right_shift(row, koybar):
    """Builds a new list by right shifting "row" by "koybar" and returns it."""
    nrow = row[:]
    for i in range(koybar):
        nrow.insert(0, nrow.pop())

    return nrow

def right_shift2(matrix):
    """Builds a new 2D list by right shifting each row of "matrix" by AES rules"""
    return [right_shift(matrix[i], i) for i in range(4)]

def g(row, rc):
    """Calucales g(row) with round constant "rc" and returns it."""
    nrow = left_shift(row, 1) # Circular left shift
    nrow = subBytes(nrow) # Substitute bytes
    nrow = jog(nrow, [rc, bzero, bzero, bzero]) # Add round key

    return nrow


def multiply(matrix1, matrix2):
    """Multiplies "matrix1" and "matrix2" using "gunTable" created previously and returns the product."""
    return [[jogList([gunTable[a.intValue()][b.intValue()] for a, b in zip(row, col)]) \
        for col in zip(*matrix2)] for row in matrix1]

def printMatrix(matrix):
    """Prints a bitVector matrix. Used for debugging."""
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

    return scheduledKeys

def encryptBlock(block, expandedKeys, nro):
    """
    Encrypts one block with "expandedKeys" keys and returns the cypher in hex array form.
    block - hex array representing data block
    """

    cypher = jog2(getMatrixForm(block), expandedKeys[0])    

    for i in range(1, nro+1): # AES algorithm of four steps in each round (except last one)
        cypher = subBytes2(cypher)
        cypher = left_shift2(cypher)
        if(i < nro): cypher = multiply(Mixer, cypher)
        cypher = jog2(cypher, expandedKeys[i])

    cypherBlock = [entry.get_bitvector_in_hex() for col in zip(*cypher) for entry in col]
    return cypherBlock

def encryptFull(line, expandedKeys, nro):
    """
    Encrypts full data with "expandedKeys" keys and returns the cypher in hex array form.
    line - hex array representing full data (possible padded with garbage)
    """

    length = len(line)
    sz = len(expandedKeys[0][0])*4
    
    result = []
    for i in range(0, length, sz):
        result.extend(encryptBlock(line[i:i+sz], expandedKeys, nro))

    return result

def decryptBlock(block, expandedKeys, nro):
    """
    Reverse process of encryptBlock().
    Returns the actual data block in hex array form.
    block - cypher block in hex array form.
    """
    
    plainText = jog2(getMatrixForm(block), expandedKeys[0])

    for i in range(1, nro+1):
        plainText = invSubBytes2(plainText)
        plainText = right_shift2(plainText)
        plainText = jog2(plainText, expandedKeys[i])
        if(i < nro): plainText = multiply(InvMixer, plainText)

    plainTextBlock = [entry.get_bitvector_in_hex() for col in zip(*plainText) for entry in col]
    return plainTextBlock

def decryptFull(line, expandedKeys, nro):
    """
    Reverse process of encryptfull().
    Returns the actual data in hex array form.
    block - full cypher text in hex array form.
    """
    expandedKeys.reverse()

    length = len(line)
    sz = len(expandedKeys[0][0])*4

    result = []
    for i in range(0, length, sz):
        result.extend(decryptBlock(line[i:i+sz], expandedKeys, nro))

    return result

def hexStringToArray(senHex):
    """ "001256" -> ["00", "12", "56"] """
    length = len(senHex)
    senHex = [senHex[i:i+2] for i in range(0, length, 2)]

    return senHex

def stringToHex(sentence):
    """ Converts string to hex array and returns it. """
    return hexStringToArray(sentence.encode().hex())

# latin-1 might produce ulta palta characters.
def hexToString(senHex): return bytes.fromhex("".join(senHex)).decode("latin-1", errors="ignore")

def takeInput():
    """
    title - file name or text data
    isFile - True if we want to process a file else false
    key - The key entered by the user
    """

    isFile = bool(int(input("Enter 1 for text or 2 for file: "))-1)
    title = input("Enter " + ("file name" if isFile else "text") + ": ")
    key = input("Enter key: ")

    return title, isFile, key

def aes(aesType, title, isFile, key):
    """
    aesType - 128 or 192 or 256
    title - text data or file name
    key - key entered by the user

    This function first schedules the key, then performs encryption and decryption on the text / file data.
    Finally outputs the results and execution time of scheduling, encryption and decryption.
    """

    print("\n\n\nAES-" + str(aesType) + ":\n")

    titleHex = stringToHex(title)
    if isFile:
        with open(title, 'rb') as f:
            titleHex = f.read().hex()
            titleHex = hexStringToArray(titleHex)

    # titleHex now contains hex array form of the data we need to encrypt.

    keyHex = stringToHex(key) # hex array form of key
    titleLen, keyLen = len(titleHex), len(keyHex)

    sz = int(aesType/8) # Block size
    nro = roundDix[aesType] # Number of rounds

    # If the size of the key is less than block size, '0' is padded.
    while keyLen > sz:
        keyHex.pop()
        keyLen -= 1
    while keyLen < sz:
        keyHex.append("30")
        keyLen += 1

    # Data needs to be a multiple of block size to perform encryption.
    # If not, '\0' is added.
    extra = 0
    while((titleLen+extra)%sz != 0):
        titleHex.append("00")
        extra += 1

    print("\nPlain text/file contents (in hex): " + "".join(titleHex))
    print("\nKey (in hex): " + "".join(keyHex))

    startTime = time.time()
    expandedKeys = scheduleKey(keyHex)
    scheduleTime = time.time()-startTime

    startTime = time.time()
    cypherHex = encryptFull(titleHex, expandedKeys, nro)
    encryptionTime = time.time()-startTime

    print("\n\nCypher text (in hex): " + "".join(cypherHex))
    print("Cypher text (in ASCII): " + hexToString(cypherHex))

    
    startTime = time.time()
    detitleHex = decryptFull(cypherHex, expandedKeys, nro)
    decryptionTime = time.time()-startTime

    print("\n\nDeciphered text/file contents (in hex): " + "".join(detitleHex))

    # Extra '\0' characters added to the data are popped
    while extra > 0:
        detitleHex.pop()
        extra -= 1

    if(isFile):
        with open("decrypted_" + str(aesType) + "_" + title, 'wb') as f:
            f.write(binascii.unhexlify("".join(detitleHex)))

        print("\nNew decrypted_" + str(aesType) + "_" + title + " file has been created.")
    else:
        print("\nDeciphered text (in ASCII): " + hexToString(detitleHex))

    print("\n\nExecution time:")
    print("Key Scheduling:", scheduleTime, "seconds")
    print("Encryption Time:", encryptionTime, "seconds")
    print("Decryption Time:", decryptionTime, "seconds")

preCalc()
preCalcSBox()

title, isFile, key = takeInput()

aes(128, title, isFile, key)
aes(192, title, isFile, key)
aes(256, title, isFile, key)
