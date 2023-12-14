from oracle_python_v1_2 import dec_oracle
# Set IV yourself. The IV below is an example.
IV = "0x1234567890abcdef"
# This is the example ciphertext.
Ciphertext = "0x1234567890abcdef"
hex_plaintext = dec_oracle(IV, Ciphertext)

print (hex_plaintext)