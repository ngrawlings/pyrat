import os
import hashlib
import datetime

def get_file_list(directory):
    file_list = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_name = os.path.basename(file_path)
            creation_date = datetime.datetime.fromtimestamp(os.path.getctime(file_path)).timestamp()
            modified_date = datetime.datetime.fromtimestamp(os.path.getmtime(file_path)).timestamp()
            sha256_hash = calculate_sha256_checksum(file_path)
            file_size = os.path.getsize(file_path)
            file_info = {
                'name': file_name,
                'creation_date': creation_date,
                'modified_date': modified_date,
                'sha256_hash': sha256_hash,
                'file_size': file_size
            }
            file_list.append(file_info)
    return file_list

def calculate_sha256_checksum(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b''):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()
