# We have to run this command on a terminal first : 
# java -cp pad_oracle.jar:bcprov-jdk15-130.jar:python_interface_v1_2.jar python_interface_v1_2;
# Then to call our fonction, we will need also need to call it from a terminal :
# python p1_20226189.py C0 and C1
# C0 and C1 will be two ciphertexts that we will be sending on our python script to 
# recover the plaintext

# I actually watched some video on youtube to better understand the attack
# especially this one : https://www.youtube.com/watch?v=4EgD4PEatA8


# Command line that is asked in the assignement.pdf file
# so we can access the function pad_oracle

import re
from oracle_python_v1_2 import pad_oracle;

# The function below shows us how to query the padding oracle
# The padding oracle accept both C0 and C1 (each 64 bits long)
# and return a 1 or a 0, indicating correct or incorrect padding
# ret_pad = pad_oracle('Ox1234567890abcdef', '0x1234567890abcdef');

#For C a ciphertext, the first 64 bits are the IV and 
# the last 64-bit block is the cipher block, C1

# import sys to get the parameters
import sys


# What we need to do is to make our block 64-bit long
# So to do that, we will need to split the ciphertext at the right length
# Actually when we are working on only one block like most of the example,
# we don't have to do it

def size_block_split(seq, length):
    return [seq[i:i+length] for i in range(0, len(seq), length)]

# The XOR function
# Way to do it found on this forum 
# https://stackoverflow.com/questions/11119632/bitwise-xor-of-hexadecimal-numbers

def xor_function(seq1, seq2):
    print ("---------------START OF XOR---------------")
    print("seq1 = ", seq1)
    print("seq2 = ", seq2)
    result = hex(int(seq1, 16) ^ int(seq2, 16))
    result = result.split('0x')[1]
    print ("result = ", result)
    print ("----------------END OF XOR----------------")
    return result

# We are splitting the cipher for the padding
# that means that we will add 0x something at the end 
# of the block

def padding(size_block, i):
    blocks = []
    for t in range(0,i+1):
        # We will pad our plaintext block with i, in the first iter of i it would be like
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

# We want to modify some bytes, then send xor them with the previous block
# and finally send them to the oracle to see if the oracle accept this value 
# and tell us that the padding is correct

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
    result = result + hex_char + ''.join(blocks)
    # print ("Result = ", result)
    return result

# We will also use put the pad_oracle function in another
# function in order to call it more easily

def pad_oracle_test(c0, c1):
    # c1 is a list, we need to transform it to a string to concatenate it
    print ("----------SENDING TO THE ORACLE!----------")
    print ("c0 = ", c0)
    str_c1 = ''.join(c1)
    print ("str_c1 = ", str_c1)
    c0 = "0x"+c0
    c1 = "0x"+str_c1
    ret_pad = pad_oracle(c0, c1) 
    return ret_pad

# This will be the main function of our attack
def oracle_padding_attack(c0_iv, c1_cipher, size_block):

    ciphertext = c1_cipher
    text_size = size_block*2

    # Creating a boolean to see if we get a hit when we try to change the ith byte from
    # the previous block
    hit = False

    # We will store the value that we sent to the pad_oracle which returned 1
    correct_value = []

    # We will store the plaintext inside
    result = []

    iv = c0_iv

    # We are cutting ciphertext in block of 16 characters, already 16 characters in the example
    # But this is in case there are multiple blocks
    ciphertext_block = size_block_split(ciphertext, text_size)
    print("length : ",len(ciphertext_block))
    print("ciphertext_block = ", ciphertext_block)


    # For each block of cypher, 1 block is 64 bits

    # I tried to do it for multiple blocks, but had weird result so I didn't submit the code
    # that why there are some function that are defined but actually they are not needed if we only
    # work on 1 block of ciphertext
    # The code in this file worked on the example 

    print ("searching for good padding value of the block", ciphertext_block)

    # We will iter through the block and change value by value and test them with the oracle
    for i in range (0, size_block):
        print ("\n-------------NEW ITER I-------------")

        # Testing every hex value to see if the oracle accepts the padding

        for j in range(0, 256):

            # 1 XOR 1 = 0 so that's why we have the j != i+1
            # len(correct_value) is the length of the list of correct_value, 
            # the value that were sent to the oracle which returned 1

            if j != i+1 or len(correct_value) > 0:
                print ("-------------NEW ITER J-------------")
                print ("iter j = ", j)
                
                last_byte_previous_block = find_bytes(size_block,i,j,correct_value)
                print("last_byte_previous_block = ", last_byte_previous_block)


                previous_block = iv
                print ("previous_block = ", previous_block)

                # We also want to force the last byte of the plaintext to be 01, 0202
                # depending on the iteration we are in

                byte_plaintext = padding(size_block,i)
                print ("byte_plaintext = ", byte_plaintext)

                # We are trying to change block[-1]
                # For example, if we search plaintext for C1,
                # We are going to change C0 which is the IV

                prev_block_modified = xor_function(last_byte_previous_block,previous_block)
                print ("prev_block_modified = ", prev_block_modified)

                temp = xor_function(prev_block_modified,byte_plaintext)

                current_cipherblock = ciphertext_block

                # We send in the oracle the ciphertext block of the plaintext we are searching for
                # together our modified IV XORED Plaintext that ends with 01 if we are in the first iter

                pad_result = pad_oracle_test(temp, current_cipherblock)

                # pad_result is in hex, so I am decoding it to use it in my IF below,
                # because else the return value would be (b'0' or b'1' and not just 0 or 1)

                pad_result = pad_result.decode("utf-8")
                print ("pad result = ", pad_result)

                #If the padding return 1, it means the padding is correct so we 
                #should store the value to add it at the end of the new block we will
                #create to pad the entire ciphertext

                if (pad_result == '1'):

                    print ("Got a hit !")
                    
                    hit = True

                    # The oracle returned 1 so the hex character related to j worked
                    # We get the hex character without the 0x and we put them in our list
                    # of valid value

                    temp_value = hex(j).split('0x')[1]
                    if (len(temp_value)%2 != 0):
                        temp_value = "0"+temp_value
                    print (temp_value)
                    correct_value.insert(0,temp_value)
                    print (correct_value)

                    # quit(), put that here to debug and to see if I indeed get some hit
                    break

        if hit == False:
                
            # The padding of the last block could be 01, it is not impossible

            print ("Maybe the padding of the last block is 01")

            # quit()

            if i == 0:

                # We assume that 01 is a correct value, so we put it in the list
                # of correct value
                correct_value.insert(0,"01")
                # print (correct_value)

        hit = False

    result.insert(0, ''.join(correct_value))
    print ("result = ", result)
    correct_value = []

# We stored the correct HEX value in result, but result is a list
# We are putting them in a string with ''.join(result)

    hex_value= ''.join(result)
    print ("Decrypted value in HEX is :", hex_value.upper())

# We convert our result in hex in ascii and remove the padding value to get
# our result in string

    final_result = ""
    # Splitting in block of size 2 because one character in ascii is 2 in hex
    # For example (hex = 41 ==> A in ascii)
    decrypted_value = size_block_split(hex_value, 2)
    # print ("decrypted value = ", decrypted_value)
    # print (len(decrypted_value))
    for i in range(0, len(decrypted_value)):
        ascii_value = bytes.fromhex(decrypted_value[i]).decode('utf-8')
        if ascii_value >= "A" and ascii_value <= "z" :
            final_result = final_result + ascii_value

    #decrypted_value = bytes.fromhex(hex_value).decode('utf-8')
    #print ("Decrypted value in ASCII is : ", decrypted_value)

    return final_result
 
               
            
print ("--------------------------------START OF THE PROGRAM--------------------------------")

# We strip 0x from the parameters because we don't need to work on them
# We will just have to put them back when we will query the oracle

c0 = sys.argv[1].lstrip("0x")
c1 = sys.argv[2].lstrip("0x")

# For example for ciphertext_01.txt, we have
# 0xe584debd2abad5b3	0xcbd746544cdadf30
# C0 = 0xe584debd2abad5b3 is the IV
# C1 = 0xcbd746544cdadf30 is the ciphertext

print ('Parameters without 0x are :')

print (c0, c1)

result = oracle_padding_attack(c0, c1, 8)
print("result = ", result)

