import jwt

with open("../keys/public_key.pem", "rb") as f:
    public_key = f.read()

with open("../licenses/license.jwt", "r") as f:
    token = f.read().strip()

payload = jwt.decode(token, public_key, algorithms=["RS256"])
print(payload)
