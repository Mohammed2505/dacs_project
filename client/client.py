import sys, requests
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


SERVER = "http://127.0.0.1:5000"

def register(username, device_id):
    r = requests.post(f"{SERVER}/register", json={"username": username, "device_id": device_id})
    print(r.json())

def login(username, device_id):
    r = requests.post(f"{SERVER}/login/request", json={"username": username, "device_id": device_id})
    data = r.json()
    print("Challenge from server:", data)
    response = data["challenge"]  # placeholder for Phase 1
    r2 = requests.post(f"{SERVER}/login/response",json={"username": username, "session": data["session"], "response": response})
    print(r2.json())


#### PHASE 4 PART #####
def load_private_key(filename, pin):
    with open(filename, "r") as f:
        data = json.load(f)

    encrypted_blob = base64.b64decode(data["Private_Key"])
    saved_pin = data["Pin"]

    # IMPORTANT: PIN must match
    if pin != saved_pin:
        raise ValueError("Incorrect PIN")

    # Extract salt + nonce + ciphertext
    salt = encrypted_blob[:16]
    nonce = encrypted_blob[16:28]
    ciphertext = encrypted_blob[28:]

    # Derive AES key from PIN
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    key = kdf.derive(pin.encode())

    aesgcm = AESGCM(key)
    private_pem = aesgcm.decrypt(nonce, ciphertext, None)

    # Convert PEM bytes → RSA private_key object
    private_key = serialization.load_pem_private_key(private_pem, password=None)

    return private_key


def request_challenge(user):
    res = requests.post(f"{SERVER}/request_challenge", json={"user": user})

    print("Raw server response:", res.text)   
    print("Status code:", res.status_code)    
    
    data = res.json()
    print("Challenge:", data)
    return base64.b64decode(data["challenge"])

def sign_challenge(private_key, challenge):
    signature = private_key.sign(
        challenge,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def send_signature(user, signature_b64):
    res = requests.post(
        f"{SERVER}/verify_signature",
        json={"user": user, "signature": signature_b64}
    )
    print("Server response:", res.json())


        
if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python client.py [register|login] <username> <device_id>")
        sys.exit(1)

    action, username, device_id = sys.argv[1], sys.argv[2], sys.argv[3]
    if action == "register":
        register(username, device_id)
    elif action == "login":
        login(username, device_id)
    elif action == "get_keys":
        print()
    
    elif action == "auth":
        # Load private key from encrypted file
        filename = f"{username}_private_key.json"
        pin = input("Enter your PIN: ")
        private_key = load_private_key(filename, pin) 

        try:
            private_key = load_private_key(filename, pin)
            print("Private key successfully decrypted.")
        except Exception as e:
            print("Error decrypting private key:", e)
            sys.exit(1)

        # Step 1: Get challenge
        challenge = request_challenge(username)

        # Step 2: Sign challenge
        try:
            signature_b64 = sign_challenge(private_key, challenge)
        except Exception as e:
            print("Error signing challenge:", e)
            sys.exit(1)

        # Step 3: Send signature back
        send_signature(username, signature_b64)

