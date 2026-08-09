"""
Dilemma CI Key Generator - runs inside GitHub Actions
Reads the private key from the SKGL_PRIVATE_KEY secret,
mints native CryptoLens keys, updates keys.json, and writes
the generated keys to generated_keys.txt.
"""
import os
import sys
import json
import base64
import hashlib
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

PRIV_ENV = "SKGL_PRIVATE_KEY"
KEY_FILE = "keys.json"

def main():
    days = int(os.environ.get("INPUT_DAYS", "365"))
    count = int(os.environ.get("INPUT_COUNT", "1"))

    priv_pem = os.environ.get(PRIV_ENV)
    if not priv_pem:
        print("FATAL: SKGL_PRIVATE_KEY secret not set")
        sys.exit(1)
    priv = serialization.load_pem_private_key(priv_pem.encode(), password=None)

    now = int(datetime.now(timezone.utc).timestamp())
    expires_ts = int((datetime.now(timezone.utc) + timedelta(days=days)).timestamp())
    expires_str = datetime.now().strftime("%Y-%m-%d")

    db = {"keys": {}, "version": 3}
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE) as f:
            db = json.load(f)

    generated = []
    for i in range(count):
        key_id = (now * 1000) + i
        lic = {
            "ProductId": 1, "ID": key_id, "Key": f"DIL-{key_id}",
            "Created": now, "Expires": expires_ts, "Period": days,
            "F1": False, "F2": False, "F3": False, "F4": False,
            "F5": False, "F6": False, "F7": False, "F8": False,
            "Notes": "", "Block": 0, "GlobalId": 0, "Customer": None,
            "ActivatedMachines": [], "TrialActivation": 0, "MaxNoOfMachines": 0,
            "AllowedMachines": [], "DataObjects": None, "SignDate": now,
            "Reseller": None,
        }
        lic_json = json.dumps(lic).encode()
        sig = priv.sign(lic_json, padding.PKCS1v15(), hashes.SHA256())
        key_str = json.dumps({
            "licenseKey": base64.b64encode(lic_json).decode(),
            "signature": base64.b64encode(sig).decode(),
            "result": 0, "message": "",
        })
        generated.append(key_str)
        short_id = f"DIL-{key_id}"
        db["keys"][hashlib.sha256(key_str.encode()).hexdigest()] = {
            "created": datetime.now().isoformat(),
            "expires": expires_str,
            "id": short_id,
            "key": key_str,
        }

    with open(KEY_FILE, "w") as f:
        json.dump(db, f, indent=2)

    with open("generated_keys.txt", "w") as f:
        for k in generated:
            f.write(k + "\n")

    print(f"OK: generated {count} key(s), valid {days} days")
    print(f"keys.json now has {len(db['keys'])} entries")

if __name__ == "__main__":
    main()
