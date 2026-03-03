import argparse
from crypto_utils import (
    generate_keys,
    save_private_key,
    save_public_key,
    load_private_key,
    load_public_key,
    sign_data,
    verify_signature
)


def generate():
    """
    Generate and save key pair.
    """
    private_key, public_key = generate_keys()
    save_private_key(private_key)
    save_public_key(public_key)
    print("Keys generated: private_key.pem & public_key.pem")


def sign(file_path, key_path):
    """
    Sign a file.
    """
    private_key = load_private_key(key_path)

    with open(file_path, "rb") as f:
        data = f.read()

    signature = sign_data(private_key, data)

    with open(file_path + ".sig", "wb") as f:
        f.write(signature)

    print(f"File signed: {file_path}.sig")


def verify(file_path, key_path):
    """
    Verify file signature.
    """
    public_key = load_public_key(key_path)

    with open(file_path, "rb") as f:
        data = f.read()

    with open(file_path + ".sig", "rb") as f:
        signature = f.read()

    if verify_signature(public_key, data, signature):
        print("Signature VALID")
    else:
        print("Signature INVALID")


def main():
    parser = argparse.ArgumentParser(description="SignaCrypt - Digital Signature Tool")

    parser.add_argument("mode", choices=["generate", "sign", "verify"])
    parser.add_argument("--file", help="File to sign/verify")
    parser.add_argument("--key", help="Path to key file")

    args = parser.parse_args()

    if args.mode == "generate":
        generate()
    elif args.mode == "sign":
        sign(args.file, args.key)
    elif args.mode == "verify":
        verify(args.file, args.key)


if __name__ == "__main__":
    main()
