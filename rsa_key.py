# rsa_key.py
from Crypto.PublicKey import RSA

usernames = ["John", "Mary"]

for username in usernames:
    key = RSA.generate(2048)
    private_path = f"private_{username}.pem"
    public_path = f"public_{username}.pem"

    with open(private_path, "wb") as priv_file:
        priv_file.write(key.export_key())
    with open(public_path, "wb") as pub_file:
        pub_file.write(key.publickey().export_key())

    print(f"[KEYGEN] Generated RSA keys for {username}")
