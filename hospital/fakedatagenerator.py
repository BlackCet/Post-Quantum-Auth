import random
import json
import csv
from pathlib import Path

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
except ImportError:
    canvas = None


compounds = ["DQ-104", "DQ-299", "DQ-401A", "DQ-772B", "PLACEBO"]
reactions = ["None", "None", "None", "None", "Nausea", "Headache", "Fatigue", "Dizziness"]


def generate_record():
    return {
        "Patient_ID": f"PT-{random.randint(10000, 99999)}",
        "Compound_ID": random.choice(compounds),
        "Trial_Phase": f"Phase_{random.randint(1, 3)}",
        "Dosage_mg": random.choice([10, 25, 50, 100]),
        "Heart_Rate_bpm": random.randint(60, 100),
        "Systolic_BP": random.randint(110, 140),
        "Diastolic_BP": random.randint(70, 90),
        "Adverse_Reaction": random.choice(reactions),
    }


def generate_txt(filename="fake_data.txt", target_size_mb=1):
    target_size_bytes = target_size_mb * 1024 * 1024
    headers = "Patient_ID,Compound_ID,Trial_Phase,Dosage_mg,Heart_Rate_bpm,Systolic_BP,Diastolic_BP,Adverse_Reaction\n"

    with open(filename, "w", encoding="utf-8") as f:
        f.write(headers)
        bytes_written = len(headers.encode("utf-8"))

        while bytes_written < target_size_bytes:
            r = generate_record()
            row = ",".join(str(v) for v in r.values()) + "\n"
            f.write(row)
            bytes_written += len(row.encode("utf-8"))

    print(f"Generated TXT: {filename} ({target_size_mb} MB)")


def generate_csv(filename="fake_data.csv", target_size_mb=1):
    target_size_bytes = target_size_mb * 1024 * 1024
    bytes_written = 0

    with open(filename, "w", newline="", encoding="utf-8") as f:
        fieldnames = list(generate_record().keys())
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        bytes_written += len(",".join(fieldnames).encode("utf-8"))

        while bytes_written < target_size_bytes:
            r = generate_record()
            writer.writerow(r)
            row = ",".join(str(v) for v in r.values()) + "\n"
            bytes_written += len(row.encode("utf-8"))

    print(f"Generated CSV: {filename} ({target_size_mb} MB)")


def generate_json(filename="fake_data.json", target_size_mb=1):
    target_size_bytes = target_size_mb * 1024 * 1024

    with open(filename, "w", encoding="utf-8") as f:
        f.write("[\n")
        bytes_written = 2
        first = True

        while bytes_written < target_size_bytes:
            record = generate_record()
            record_json = json.dumps(record)

            if not first:
                record_json = ",\n" + record_json
            else:
                first = False

            f.write(record_json)
            bytes_written += len(record_json.encode("utf-8"))

        f.write("\n]\n")

    print(f"Generated JSON: {filename} ({target_size_mb} MB)")


def generate_pdf(filename="fake_report.pdf", target_size_mb=1):
    if canvas is None:
        raise ImportError("Install reportlab first: pip install reportlab")

    from reportlab.lib import pagesizes

    target_size_bytes = target_size_mb * 1024 * 1024
    width, height = pagesizes.letter

    c = canvas.Canvas(filename, pagesize=pagesizes.letter, pageCompression=0)

    page = 1
    max_pages = target_size_mb * 80   # safety limit

    for _ in range(max_pages):
        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, height - 50, "Synthetic Pharmacovigilance Report")

        c.setFont("Helvetica", 9)
        c.drawString(50, height - 70, "Generated for PQC-secured healthcare data pipeline testing")
        c.drawString(50, height - 85, "Synthetic adverse event monitoring report")

        y = height - 120

        c.setFont("Helvetica-Bold", 8)
        headers = ["Patient", "Compound", "Phase", "Dose", "HR", "BP", "Reaction"]
        x_positions = [50, 115, 190, 245, 295, 335, 405]

        for x, hname in zip(x_positions, headers):
            c.drawString(x, y, hname)

        y -= 18
        c.setFont("Helvetica", 8)

        for _ in range(32):
            r = generate_record()
            values = [
                r["Patient_ID"],
                r["Compound_ID"],
                r["Trial_Phase"],
                str(r["Dosage_mg"]),
                str(r["Heart_Rate_bpm"]),
                f"{r['Systolic_BP']}/{r['Diastolic_BP']}",
                r["Adverse_Reaction"],
            ]

            for x, value in zip(x_positions, values):
                c.drawString(x, y, value)

            y -= 16

        c.setFont("Helvetica-Oblique", 8)
        c.drawString(50, 40, "Synthetic data only. No real patient information included.")
        c.drawRightString(width - 50, 40, f"Page {page}")

        c.showPage()
        page += 1

    c.save()

    # If still smaller than target, pad safely for testing size
    current_size = Path(filename).stat().st_size
    if current_size < target_size_bytes:
        padding_needed = target_size_bytes - current_size
        with open(filename, "ab") as f:
            f.write(b"\n% Synthetic padding for benchmark file size\n")
            f.write(b"0" * padding_needed)

    print(f"Generated PDF: {filename} ({target_size_mb} MB)")


def generate_pharma_data(filename="fake_data.txt", target_size_mb=1):
    ext = Path(filename).suffix.lower()

    if ext == ".txt":
        generate_txt(filename, target_size_mb)
    elif ext == ".csv":
        generate_csv(filename, target_size_mb)
    elif ext == ".json":
        generate_json(filename, target_size_mb)
    elif ext == ".pdf":
        generate_pdf(filename, target_size_mb)
    else:
        raise ValueError("Supported formats: .txt, .csv, .json, .pdf")


if __name__ == "__main__":
    generate_pharma_data("adverse_events.csv", 10)
    generate_pharma_data("patient_report.pdf", 1)
    generate_pharma_data("records.json", 25)
    generate_pharma_data("fake_data.txt", 50)