import argparse
import json
from pathlib import Path


from crypto_backend import BASELINE, IMPROVED, keygen


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate PQC key material.")
    parser.add_argument(
        "--implementation",
        choices=(BASELINE, IMPROVED, "both"),
        default=BASELINE,
    )
    parser.add_argument("--output", type=Path, default=Path("keys.json"))
    args = parser.parse_args()

    implementations = (BASELINE, IMPROVED) if args.implementation == "both" else (args.implementation,)
    keys = {}
    if args.output.exists():
        with args.output.open(encoding="utf-8") as key_file:
            keys = json.load(key_file)

    for implementation in implementations:
        (kem_public, kem_secret), (signature_public, signature_secret) = keygen(
            implementation
        )
        if implementation == BASELINE:
            fields = {
                "server_ek": kem_public,
                "server_dk": kem_secret,
                "hospital_sk": signature_secret,
                "pharma_pk": signature_public,
            }
        else:
            fields = {
                "oqs_server_ek": kem_public,
                "oqs_server_dk": kem_secret,
                "oqs_hospital_sk": signature_secret,
                "oqs_pharma_pk": signature_public,
            }
        keys.update({name: value.hex() for name, value in fields.items()})

    with args.output.open("w", encoding="utf-8") as key_file:
        json.dump(keys, key_file, indent=2)
        key_file.write("\n")
    print(f"Generated {args.implementation} key material in {args.output}.")


if __name__ == "__main__":
    main()