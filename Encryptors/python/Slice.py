from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad
from Crypto.Protocol.KDF import PBKDF2
import configparser
import sys
import os

# Read the configuration
config = configparser.ConfigParser()
config.read('../../config.ini')
num_files = int(config['DEFAULT']['NumberOfFiles'])
password = config['DEFAULT']['EncryptionKey'].encode()  #

# Arguments from command line
file_path = sys.argv[1]

# Read binary file
with open(file_path, 'rb') as file:
    data = file.read()

# Key derivation
salt = os.urandom(16)  # Should be securely generated and consistent for decryption
key = PBKDF2(password, salt, dkLen=16, count=100000, hmac_hash_module=SHA256)

# Encryption
iv = os.urandom(16)
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(data, AES.block_size))

# Save IV to file
with open('../../Decryptor/Downloads/iv.bin', 'wb') as iv_file:
    iv_file.write(iv)

# Save salt to file
with open('../../Decryptor/Downloads/salt.bin', 'wb') as salt_file:
    salt_file.write(salt)

# Write encrypted file without the IV
enc_file_path = f'{file_path}.enc'
with open(enc_file_path, 'wb') as enc_file:
    enc_file.write(ciphertext)

# Calculate the size of each chunk
file_size = os.path.getsize(enc_file_path)
chunk_size = file_size // num_files
remainder = file_size % num_files

# Split file into chunks
for i in range(num_files):
    part_size = chunk_size + (1 if i < remainder else 0)
    with open(enc_file_path, 'rb') as enc_file:
        # Move to the start of the current chunk
        enc_file.seek(i * chunk_size)
        # Read the chunk
        chunk_data = enc_file.read(part_size)
        # Write the chunk to a new part file
        with open(f'{file_path}_part{i}', 'wb') as part_file:
            print(f"Saving " + file_path)
            part_file.write(chunk_data)

print(f"Encrypted file split into {num_files} parts.")
print(f"IV saved to iv.bin.")
print(f"Key is %s " % password)
print(f"salt saved to salt.bin.")
