"""
    createing a dummy database for users
"""
import json
import hashlib
from cryptography.fernet import Fernet

KEY_1 = Fernet.generate_key().decode()
KEY_2 = Fernet.generate_key().decode()
KEY_3 = Fernet.generate_key().decode()
KEY_4 = Fernet.generate_key().decode()
KEY_5 = Fernet.generate_key().decode()
#gagandeep, krishna, yaneisi
DATA = {
    'ali': ["00"+hashlib.sha256(("00"+"1234").encode()).hexdigest(), KEY_1],
    'bianca': ["11"+hashlib.sha256(("11"+"4321").encode()).hexdigest(), KEY_2],
    'gagandeep': ["22"+hashlib.sha256(("22"+"1234").encode()).hexdigest(), KEY_3],
    'krishna': ["33"+hashlib.sha256(("33"+"4321").encode()).hexdigest(), KEY_4],
    'yaneisi': ["44"+hashlib.sha256(("22"+"1234").encode()).hexdigest(), KEY_5],
    }

with open("user_db.json", "w") as fp:
    json.dump(DATA, fp)
    fp.close()

print(json.dumps(DATA, indent=5))
