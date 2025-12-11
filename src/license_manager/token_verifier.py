import jwt

with open("public_key.pem", "rb") as f:
    public_key = f.read()

with open("license.jwt", "r") as f:
    token = f.read().strip()

payload = jwt.decode(token, public_key, algorithms=["PS256"])
print(payload)
