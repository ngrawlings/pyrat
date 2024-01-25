import json
import hashlib
import sys
import os
import time

# Prompt for ASCII salt
salt = input("Enter ASCII salt: ")

file_path = sys.argv[1]  # Retrieve the file path from command line argument

# Create a backup file name with the original file name and Unix timestamp
backup_file_name = f"{os.path.splitext(file_path)[0]}_bak_{int(time.time())}"

# Copy the original file to the backup file
os.rename(file_path, backup_file_name)

# Open the backup JSON file
with open(backup_file_name) as file:
    data = json.load(file)

# Iterate through objects under the "keys" key
for obj in data["keys"]:
    obj["key"] = hashlib.sha256((obj["key"] + salt).encode()).hexdigest()
    obj["iv"] = hashlib.sha256((obj["iv"] + salt).encode()).hexdigest()

# Save the modified data to the original file path
with open(file_path, "w") as file:
    json.dump(data, file)
        

