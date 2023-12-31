"""
Contains functions related to slicing and encrypting the supplied file for delivery
"""
import configparser
import sys
import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad
from Crypto.Protocol.KDF import PBKDF2


# Read the configuration
config = configparser.ConfigParser()
config.read('../../config.ini')
num_files = int(config['DEFAULT']['NumberOfFiles'])
password = config['DEFAULT']['EncryptionKey'].encode()  #


DOWNLOAD_DIRECTORY = '../../Decryptor/Downloads'
# Ensure the base directory exists, if not, create it
os.makedirs(DOWNLOAD_DIRECTORY, exist_ok=True)
parts_directory = os.path.join(DOWNLOAD_DIRECTORY, 'parts')
os.makedirs(parts_directory, exist_ok=True)

PIZZA_SLICE_ART = '''
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⣀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⣷⡄
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⡇
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⡿⠃
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣷⣆⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⣹⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀
⠀⠀⢀⣠⣶⣿⣿⣿⣿⣿⣶⣦⣾⣿⡿⠟⢿⣿⣿⣏⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠙⢿⣿⠗⠀⠀⠀⠀⠀⠀⠀
⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢸⣿⣿⣿⣿⣿⡏⠀⠈⣿⣿⣿⣿⣿⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢸⣿⣿⣿⣿⣿⣿⣶⣾⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠙⠻⣿⣿⣿⣿⣿⣿⣿⡿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        '''


def print_usage():
    """
    Prints the expected usage
    :return:
    """

    print("Slice")
    print("Usage: python slice.py <file_to_encrypt>")
    sys.exit(1)


# Check if the correct number of arguments are provided
if len(sys.argv) != 2:
    print_usage()

# Arguments from command line
file_path = sys.argv[1]

print(PIZZA_SLICE_ART)

# Read binary file
with open(file_path, 'rb') as file:
    data = file.read()

# Key derivation
salt = os.urandom(16)  # Should be securely generated and consistent for decryption
key: bytes = PBKDF2(password, salt, dkLen=16, count=100000, hmac_hash_module=SHA256)
print(f"Type of key: {type(key)}")
# Check the type of key and exit if not bytes
if not isinstance(key, bytes):
    print("Error: Key is not of byte type.")
    sys.exit(1)

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

        part_file_path = os.path.join(parts_directory, f'{file_path}_part{i}')
        with open(part_file_path, 'wb') as part_file:
            print(f"Saving {part_file_path}")
            part_file.write(chunk_data)


print(f"Encrypted file split into {num_files} parts.")
print("IV saved to iv.bin.")
print(f"Key is {password}")
print("salt saved to salt.bin.")
