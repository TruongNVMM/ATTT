import os
import sys
import base64
import argparse

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.asymmetric.ECDSA.privateKey import PrivateKey
from src.asymmetric.DSA import DSA
from src.asymmetric.RSA.RSA import RSA


''' PEM FORMAT '''
def custom_to_pem(algo_name, key_data, is_private=True):
    b64_content = base64.b64encode(str(key_data).encode('utf-8')).decode('utf-8')
    lines = [b64_content[i:i+64] for i in range(0, len(b64_content), 64)]

    header = f"-----BEGIN {algo_name} PRIVATE KEY-----" if is_private else f"-----BEGIN {algo_name} PUBLIC KEY-----"
    footer = f"-----END {algo_name} PRIVATE KEY-----" if is_private else f"-----END {algo_name} PUBLIC KEY-----"

    return f"{header}\n" + "\n".join(lines) + f"\n{footer}\n"


''' KEY GENERATION '''
def generate_keys(algorithm):
    if algorithm == "ECDSA":
        private_key = PrivateKey()
        public_key = private_key.publicKey()

        private_pem = private_key.toPem()
        public_pem = public_key.toPem()

    elif algorithm == "DSA":
        try:
            dsa = DSA.DSA() if hasattr(DSA, 'DSA') else DSA()
            priv, pub = dsa.generate_keypair()
        except Exception:
            from src.asymmetric.DSA import DSA as dsa_class
            dsa = dsa_class()
            priv, pub = dsa.generate_keypair()

        private_pem = custom_to_pem("DSA", priv, True)
        public_pem = custom_to_pem("DSA", pub, False)

    elif algorithm == "RSA":
        try:
            rsa = RSA(bit_length=5)  # test nhanh
        except Exception:
            rsa = RSA()

        pub, priv = rsa.generate_keypair()
        private_pem = custom_to_pem("RSA", priv, True)
        public_pem = custom_to_pem("RSA", pub, False)

    else:
        raise ValueError("Invalid algorithm")

    return private_pem, public_pem


''' SAVE FILE '''
def save_keys(path, para, private_pem, public_pem):
    public_dir = os.path.join(path)
    private_dir = os.path.join(path)

    os.makedirs(public_dir, exist_ok=True)
    os.makedirs(private_dir, exist_ok=True)

    private_filepath = os.path.join(private_dir, f'private_key_{para}.pem')
    public_filepath = os.path.join(public_dir, f'public_key_{para}.pem')

    with open(private_filepath, 'w', encoding='utf-8') as f:
        f.write(private_pem)

    with open(public_filepath, 'w', encoding='utf-8') as f:
        f.write(public_pem)

    print(f"[+] Saved {para} keys:")
    print(f"    Private: {private_filepath}")
    print(f"    Public : {public_filepath}")


# ===================== MAIN =====================
def main():
    parser = argparse.ArgumentParser(description="Key Generator CLI")

    parser.add_argument(
        "--algorithm",
        type=str,
        required=True,
        choices=["RSA", "DSA", "ECDSA"],
        help="Algorithm type"
    )

    parser.add_argument(
        "--path",
        type=str,
        required=True,
        help="Directory to save keys"
    )

    parser.add_argument(
        "--para",
        type=str,
        required=True,
        choices=["sender", "receiver"],
        help="Generate keys for sender or receiver"
    )

    args = parser.parse_args()

    private_pem, public_pem = generate_keys(args.algorithm)
    save_keys(args.path, args.para, private_pem, public_pem)

    print("[+] Done!")


if __name__ == "__main__":
    main()