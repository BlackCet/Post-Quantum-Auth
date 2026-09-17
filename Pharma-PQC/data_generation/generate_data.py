# Pharma-PQC/data_generation/generate_data.py

import os
import csv
import json
import random
import string

def generate_random_string(size):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size))

def create_txt(filepath, target_size_mb):
    chars = target_size_mb * 1024 * 1024
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(generate_random_string(chars))

def create_csv(filepath, target_size_mb):
    target_bytes = target_size_mb * 1024 * 1024
    current_bytes = 0
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Patient_ID", "Adverse_Event_Code", "Clinical_Notes", "Timestamp"])
        
        while current_bytes < target_bytes:
            row = [
                random.randint(10000, 99999),
                generate_random_string(8),
                generate_random_string(50),
                random.randint(1600000000, 1700000000)
            ]
            writer.writerow(row)
            current_bytes = f.tell()

def create_json(filepath, target_size_mb):
    target_bytes = target_size_mb * 1024 * 1024
    data = []
    current_bytes = 0
    
    while current_bytes < target_bytes:
        entry = {
            "patient_id": random.randint(10000, 99999),
            "event_code": generate_random_string(8),
            "clinical_notes": generate_random_string(50)
        }
        data.append(entry)
        current_bytes += len(str(entry)) 
        
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f)

def create_pdf_dummy(filepath, target_size_mb):
    target_bytes = target_size_mb * 1024 * 1024
    with open(filepath, 'wb') as f:
        f.write(b"%PDF-1.4\n")
        f.write(os.urandom(target_bytes - 9))

if __name__ == "__main__":
    output_dir = "data_generation"
    os.makedirs(output_dir, exist_ok=True)
    sizes = [1, 10]
    
    print("Starting synthetic pharmacovigilance data generation...")
    for size in sizes:
        print(f"Generating {size}MB TXT...")
        create_txt(f"{output_dir}/dataset_{size}MB.txt", size)
        
        print(f"Generating {size}MB CSV...")
        create_csv(f"{output_dir}/dataset_{size}MB.csv", size)
        
        print(f"Generating {size}MB JSON...")
        create_json(f"{output_dir}/dataset_{size}MB.json", size)
        
        print(f"Generating {size}MB PDF (Raw Bytes)...")
        create_pdf_dummy(f"{output_dir}/dataset_{size}MB.pdf", size)
        
    print(f"Data generation complete. All files saved to {output_dir}/")