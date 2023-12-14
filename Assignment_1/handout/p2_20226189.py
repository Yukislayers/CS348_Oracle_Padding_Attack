# In the terminal, type first : 
# java -cp dec_oracle.jar:bcprov-jdk15-130.jar:python_interface_v1_2.jar python_interface_v1_2

from oracle_python_v1_2 import dec_oracle
import sys
import binascii
import math

#If a block is not 64 bits, we have to pad it in order to send it to the oracle
def pad_block(hex_msg,block_size):
    print ("We are in the pad_msg function")
    msg_blocks = hex_msg
    print (msg_blocks)
    # One full block is 16 characters, so we are searching how much we need to add
    msg_len = len(msg_blocks)
    print (msg_len)
    padstring = ''
    unhex_msg = hex_msg.decode("utf-8")
    if(msg_len != 16):
        # test = (msg_len % block_size)
        # print ("msg_len modulo block_size =", test)
        # math floor to get only the number before decimals
        n = math.floor((16 - msg_len)/2)
        print(n)
        i = 0
        while( i < n):
            # We are searching to pad our message, if we need 3 block of 2 for the padding
            # pad_block will be 03 and pad string will be 030303
            # So if we had like 3928374837 ==> 3928374837030303 in the return hex_msg + hex_padstring
            pad_value = '0' + str(n)
            # print ("pad_value = ", pad_value)
            padstring = padstring + pad_value
            # print ("padstring = ",padstring)
            i = i + 1

        print ("Unpadded block is : ", unhex_msg)

        print ("Padded block is : ", unhex_msg+padstring)
        
        # Worked with string all the way and it seems to work, not sure if it is right tho
        return unhex_msg+padstring 
    else:
        return unhex_msg

#split cipher according to block_size
def split_len(seq, length):
    return [seq[i:i+length] for i in range(0, len(seq), length)]

#We will query the dec oracle with the block of our message
def enc_msg_cbc(iv,hex_msg_blocks):
    enc_msg_blocks = []
    i = 0
    # print (len(hex_msg_blocks))
    for i in range(0,len(hex_msg_blocks)):
        enc_msg = ''
        print("In the for loop, iter : ", i)
        # Dec_orable accepts in parameter 2 strings
        # So we have to make our hex_msg_blocks[i] in to a string first
        # Transform the bytes in string
        if(i == 0):
            unhex_msg = hex_msg_blocks[i]
            print("sending to the oracle : 0x"+iv, "0x"+unhex_msg)
            enc_msg = dec_oracle("0x"+iv,"0x"+unhex_msg)
            enc_msg_blocks.insert(i,enc_msg)
        else:
            print("sending to the oracle : 0x"+iv, "0x"+hex_msg_blocks[i])
            # No need to add the "0x" in front of enc_msg_blocks because enc_msg_blocks already has the 
            # "0x" and it is a string.
            # Not sure if what I am doing is right since I am working with string and I send string to
            # the oracle instead of hex value
            enc_msg = dec_oracle(enc_msg_blocks[i-1].decode("utf-8"),"0x"+hex_msg_blocks[i])
            print(enc_msg)
            enc_msg_blocks.insert(i,enc_msg)
            print(enc_msg_blocks)
    return enc_msg_blocks

# Choose an IV of your choice, has to be form a block of 64 bits
iv = 'AC21AB15BC21EA11'

# Set the block size value
block_size = 16

# We will store the result in a list, if we have multiple blocks
result = []

# Get the string that we are giving in parameter
msg = sys.argv[1]
# Encoding the string in hex
hex_msg = binascii.hexlify(msg.encode())
hex_msg = hex_msg.upper()

print ("We are going to encrypt this : "+msg)

print ("The text that we want to encrypt in hex is", hex_msg)

print ("The IV that we chose and that forms a block of 64 bit is : 0x"+iv.lower())

#Split into blocks based on size
msg_blocks = split_len(hex_msg,block_size)

#We can see our different block
print (msg_blocks)

#send the last block to see if padding needs to be done
msg_blocks[-1] = pad_block(msg_blocks[-1],8)
#We can see that the padding has been done
print ("Print the hex_msg_block", msg_blocks)

# I am passing the hex value in string but with the same value
# different from the unhexlify so instead of having something like
# b'0230', I have 0230 and the oracle accept string and not byte

for i in range(0, len(msg_blocks)):
    if (i == len(msg_blocks)-1):
        print(msg_blocks[i])
    else:
        msg_blocks[i] = msg_blocks[i].decode("utf-8")
        print(msg_blocks[i])
    
#Sending our hex message to the oracle
result = enc_msg_cbc(iv,msg_blocks)

# Printing the encrypted message
# It does not seem to work, don't really know where I failed
print ("Encrypted msg is: ", result)


