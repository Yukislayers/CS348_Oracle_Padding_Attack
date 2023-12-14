# test = hex(0).split('0x')[1]

# temp = hex(255).strip('0x')

# print (test)
# print (temp)

import re

correct_value = ['ef', '4e', '5c', 'ac', '1d', '9c']
print (correct_value[5])
print (int(correct_value[-1],16))

bk = "00000000000000ff"
value = re.findall('..',bk)
print (value)

temp_value = hex(1).split('0x')[1]
if (len(temp_value)%2 != 0):
    temp_value = "0"+temp_value
print (temp_value)

def xor_two_str(a,b):
    xored = []
    for i in range(max(len(a), len(b))):
        xored_value = ord(a[i%len(a)]) ^ ord(b[i%len(b)])
        xored.append(hex(xored_value)[2:])
    return ''.join(xored)
    
print ("1st method")
print (xor_two_str("0000000000000001","e584debd2abad5b3"))

print(hex(0xe584debd2abad5b3 ^ 0x0000000000000001))

print(hex(0x0000000000000001 ^ 0xe584debd2abad5b3))

print(hex(0x0000000000000001 ^ 0xe584debd2abad5b3))

seq1 = "0000000000000001"
seq2 = "e584debd2abad5b3"
result = hex(int(seq1, 16) ^ int(seq2, 16))
result = result.split('0x')[1]
print (result)

def padding(size_block, i):
    blocks = []
    for t in range(0,i+1):
        # We will pad our block with i, in the first iter of i it would be like
        # 1st iter = 0000000000000001
        # 2nd iter = 0000000000000202
        # etc
        temp = hex(i+1).split('0x')[1]
        # print (temp)
        if (len(temp)%2) != 0:
            blocks.append("0")
        else:
            blocks.append(' ')
        blocks.append(hex(i+1).split('0x')[1])
        # print ("Blocks = ", blocks)
    return "00"*(size_block-(i+1)) + ''.join(blocks)

print (padding(8, 2))


def find_bytes(size_block, i, pos, blocks):
    # We have our pos = j, and j is going from 0 to 256
    # hex(1) = 0x1 so we have to get rid of the 0x in front that we don't want to use
    hex_char = hex(pos).split('0x')[1]
    print ("hex_char = ", hex_char)
    # print (len(hex_char))

    # We are forming a block that we will XOR with the ciphertext, so at every 
    # iteration, we will modify the last 2 characters of our result string to pass
    # every characters in hex from 0 to ff
    # In blocks we are storing our valid_value that we found on the previous iteration
    result = "00"*(size_block-(i+1)) 
    if (len(hex_char)%2 != 0):
        result = result + "0"
    else:
        result = result
    result = result + hex_char + ' '.join(blocks)
    # print ("Result = ", result)
    return result

blocks = ['ff']
print (find_bytes(8, 1, 128, blocks))