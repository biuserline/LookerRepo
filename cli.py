import argparse
import json
from nebula_vault.crypto import NebulaCrypto
from nebula_vault.utils import encode_base64, decode_base64


def main():
    parser = argparse.ArgumentParser(description="NebulaVault CLI Tool")
    parser.add_argument("mode", choices=["encrypt", "decrypt"])
    parser.add_argument("input", help="Input text")
    parser.add_argument("password", help="Password")

    args = parser.parse_args()

    crypto = NebulaCrypto()

    if args.mode == "encrypt":
        result = crypto.encrypt(args.input.encode(), args.password)

        output = {
            "salt": encode_base64(result["salt"]),
            "iv": encode_base64(result["iv"]),
            "ciphertext": encode_base64(result["ciphertext"])
        }

        print(json.dumps(output, indent=4))

    elif args.mode == "decrypt":
        encrypted_data = json.loads(args.input)

        decoded_data = {
            "salt": decode_base64(encrypted_data["salt"]),
            "iv": decode_base64(encrypted_data["iv"]),
            "ciphertext": decode_base64(encrypted_data["ciphertext"])
        }

        plaintext = crypto.decrypt(decoded_data, args.password)
        print(plaintext.decode())


if __name__ == "__main__":
    main()
