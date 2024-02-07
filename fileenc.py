import os
import argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import shutil
from Crypto import Random
import os

CHUNK_SIZE = 4096

def encrypt_file(file_path, key, iv):
    # Create the encrypted file path
    encrypted_file_path = file_path + '.encrypted'

    # Open the input and output files
    with open(file_path, 'rb') as input_file, open(encrypted_file_path+'.stage1', 'wb') as output_file:
        # Encrypt using Serpent
        serpent_cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypt_chunk(input_file, output_file, serpent_cipher)

    # Open the input and output files again to continue encryption
    with open(encrypted_file_path+'.stage1', 'rb') as input_file, open(encrypted_file_path+'.stage2', 'ab') as output_file:
        # Encrypt using Twofish
        twofish_cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypt_chunk(input_file, output_file, twofish_cipher)

    # Open the input and output files again to continue encryption
    with open(encrypted_file_path+'.stage2', 'rb') as input_file, open(encrypted_file_path, 'ab') as output_file:
        # Encrypt using AES in CBC mode
        aes_cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypt_chunk(input_file, output_file, aes_cipher)

    # Delete stage 1 and stage 2 files
    os.remove(encrypted_file_path+'.stage1')
    os.remove(encrypted_file_path+'.stage2')

    print('File encrypted successfully.')

def decrypt_file(file_path, key, iv):
    # Create the decrypted file path
    decrypted_file_path = file_path + '.decrypted'

    # Open the input and output files
    with open(file_path, 'rb') as input_file, open(decrypted_file_path+'.stage1', 'wb') as output_file:
        # Decrypt using AES in CBC mode
        aes_cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypt_chunk(input_file, output_file, aes_cipher)

    # Open the input and output files again to continue decryption
    with open(decrypted_file_path+'.stage1', 'rb') as input_file, open(decrypted_file_path+'.stage2', 'ab') as output_file:
        # Decrypt using Twofish
        twofish_cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypt_chunk(input_file, output_file, twofish_cipher)

    # Open the input and output files again to continue decryption
    with open(decrypted_file_path+'.stage2', 'rb') as input_file, open(decrypted_file_path, 'ab') as output_file:
        # Decrypt using Serpent
        serpent_cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypt_chunk(input_file, output_file, serpent_cipher)

    # Delete stage 1 and stage 2 files
    os.remove(decrypted_file_path+'.stage1')
    os.remove(decrypted_file_path+'.stage2')

    print('File decrypted successfully.')

def encrypt_chunk(input_file, output_file, cipher):
    while True:
        chunk = input_file.read(CHUNK_SIZE)
        if not chunk:
            break
        padded_chunk = pad(chunk, cipher.block_size)
        encrypted_chunk = cipher.encrypt(padded_chunk)
        output_file.write(encrypted_chunk)

def decrypt_chunk(input_file, output_file, cipher):
    while True:
        chunk = input_file.read(CHUNK_SIZE)
        if not chunk:
            break
        decrypted_chunk = cipher.decrypt(chunk)
        unpadded_chunk = unpad(decrypted_chunk, cipher.block_size)
        output_file.write(unpadded_chunk)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='File encryption/decryption')
    parser.add_argument('file_path', type=str, help='Path to the file')
    parser.add_argument('--key', type=str, nargs='?', default=None, help='Encryption key')
    parser.add_argument('--iv', type=str, nargs='?', default=None, help='Initialisation vector')
    parser.add_argument('--mode', type=str, nargs='?', default=None, help='enc/dec')
    args = parser.parse_args()

    if args.key is None:
        key = Random.get_random_bytes(32)
        print(key.hex())
    else:
        key = bytes.fromhex(args.key)

    if args.iv is None:
        iv = Random.get_random_bytes(16)
        print(iv.hex())
    else:
        iv = bytes.fromhex(args.iv)

    if args.mode == 'dec':
        decrypt_file(args.file_path, key, iv)
    else:
        encrypt_file(args.file_path, key, iv)
