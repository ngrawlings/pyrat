import csv
import hashlib
import os
import time
import argparse

def create_csv(directory, output):
    with open(output, 'w', newline='') as csvfile:
        fieldnames = ['File Name', 'Created Timestamp', 'Changed Timestamp', 'SHA256 Checksum']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                created_timestamp = os.path.getctime(file_path)
                changed_timestamp = os.path.getmtime(file_path)
                sha256_checksum = calculate_sha256_checksum(file_path)

                writer.writerow({
                    'File Name': file,
                    'Created Timestamp': time.ctime(created_timestamp),
                    'Changed Timestamp': time.ctime(changed_timestamp),
                    'SHA256 Checksum': sha256_checksum
                })

def calculate_sha256_checksum(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b''):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

parser = argparse.ArgumentParser()
parser.add_argument('--dir', help='Directory path to scan')
parser.add_argument('--output', help='Output file path')
args = parser.parse_args()

create_csv(args.dir, args.output)
