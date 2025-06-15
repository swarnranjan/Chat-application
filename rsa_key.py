from Crypto.PublicKey import RSA

username = "John"
key = RSA.generate(2048)
with open(f"private_{username}.pem", "wb") as priv:
    priv.write(key.export_key())
with open(f"public_{username}.pem", "wb") as pub:
    pub.write(key.publickey().export_key())

username = "Mary"
key = RSA.generate(2048)
with open(f"private_{username}.pem", "wb") as priv:
    priv.write(key.export_key())
with open(f"public_{username}.pem", "wb") as pub:
    pub.write(key.publickey().export_key())
