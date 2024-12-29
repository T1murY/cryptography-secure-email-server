import base64
import hashlib
import os
from datetime import datetime

import pytz
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, padding, hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)


def main_menu():
    server_url = "http://localhost:8080"
    while True:
        print("\n----------- Main Menu -----------")
        print("1. Login")
        print("2. Register")
        print("Q - Quit")
        choice = input("Please select an option (1 or 2): ").strip()

        if choice == "1":
            email = input("Enter your email: ").strip()
            password = input("Enter your password: ").strip()
            try:
                email_hash = hashlib.md5(email.encode()).hexdigest()
                dh_private_key_file = f"{email_hash}_dh_private.pem"
                rsa_private_key_file = f"{email_hash}_rsa_private.pem"

                dh_private_key = load_key_from_file(dh_private_key_file)
                rsa_private_key = load_key_from_file(rsa_private_key_file)

                login_response = login_user(server_url, email, password)
                print("Login successful:", login_response)

                access_token = login_response["accessToken"]

                headers = {
                    'Authorization': f'Bearer {access_token}'
                }

                while True:
                    try:
                        print("\nWhat would you like to do?")
                        print("1 - Send an email")
                        print("2 - List my emails")
                        print("3 - Logout")
                        choice = input("Choose an option (1, 2 or 3): ").strip()

                        if choice == "1":
                            recipient_email = input("Enter recipient's email: ").strip()
                            recipient_public_key = check_recipient_exists(server_url, headers, recipient_email)
                            # Store the Diffie-Hellman public key
                            print(f"Recipient found. Diffie-Hellman Public Key: {recipient_public_key}")

                            shared_secret = compute_shared_secret(dh_private_key, recipient_public_key)
                            aes_key = create_aes_key(shared_secret)

                            message = input("Enter your message: ").strip()
                            encrypted_message = encrypt_message(message, aes_key)
                            signature = sign_message(encrypted_message, rsa_private_key)

                            send_email(server_url, headers, recipient_email, encrypted_message, signature)
                        elif choice == "2":
                            emails = get_my_emails(server_url, headers)
                            if (len(emails) == 0):
                                print("No emails found.")
                                continue
                            print("\nYour emails:")
                            print("----------------")
                            turkey_tz = pytz.timezone("Europe/Istanbul")
                            for e in emails:
                                id = e["id"]
                                from_user = e["fromUser"]
                                date_sent = e["date"]
                                dh_sender_public_key = e["diffieHellmanPublicKey"]
                                rsa_sender_public_key = e["rsaPublicKey"]

                                encrypted_message = convert_base64_to_bytes(e["encryptedMessage"])
                                signature = convert_base64_to_bytes(e["signature"])
                                is_verified = verify_signature(encrypted_message, signature, rsa_sender_public_key)

                                if (is_verified):
                                    shared_secret = compute_shared_secret(dh_private_key,
                                                                          str.encode(dh_sender_public_key))
                                    aes_key = create_aes_key(shared_secret)

                                    original_message = decrypt_message(encrypted_message, aes_key)

                                    utc_time = datetime.fromisoformat(date_sent.replace("Z", "+00:00"))
                                    turkey_time = utc_time.astimezone(turkey_tz)
                                    formatted_time = turkey_time.strftime("%Y-%m-%d %H:%M:%S")

                                    print(f"Sender: {from_user}")
                                    print(f"Date: {formatted_time}")
                                    print(f"Message: {original_message}")
                                    print("---------------------")
                                else:
                                    print(f"Email not verified. This email have been changed tampered with. id: {id}")
                        elif choice == "3":
                            print("Logging out...")
                            break
                        else:
                            print("Invalid choice. Please try again.")
                    except Exception as e:
                        print("An error occurred:", e)
            except FileNotFoundError:
                print(f"No account found for {email}. Please register first.")
                continue
            except Exception as e:
                print(f"Login failed: {str(e)}, Please try again.")
                continue
        elif choice == "2":
            email = input("Enter your email: ").strip()
            password = input("Enter your password: ").strip()
            try:
                # Generate new keys
                generator, prime = fetch_diffie_hellman_params(server_url)

                dh_private_key, dh_public_key = generate_diffie_hellman_keys(generator, prime)
                rsa_private_key, rsa_public_key = generate_rsa_keys()

                # Serialize keys
                serialized_dh_public_key = serialize_key(dh_public_key)
                serialized_dh_private = serialize_key(dh_private_key, is_private=True)
                serialized_rsa_public_key = serialize_key(rsa_public_key)
                serialized_rsa_private_key = serialize_key(rsa_private_key, is_private=True)

                # Save keys to files
                email_hash = hashlib.md5(email.encode()).hexdigest()
                save_key_to_file(f"{email_hash}_dh_private.pem", serialized_dh_private)
                save_key_to_file(f"{email_hash}_rsa_private.pem", serialized_rsa_private_key)
                save_key_to_file(f"{email_hash}_dh_public.pem", serialized_dh_public_key)
                save_key_to_file(f"{email_hash}_rsa_public.pem", serialized_rsa_public_key)

                # Register user
                response = register_user(
                    server_url,
                    email,
                    password,
                    serialized_dh_public_key,
                    serialized_rsa_public_key,
                )
                print("Registration successful:", response)
                continue
            except Exception as e:
                print(f"Registration failed: {str(e)}")
        elif choice.lower() == "q":
            exit(0)
        else:
            print("Invalid choice. Please choose a valid option.")


def save_key_to_file(filename, key):
    """
    Save the serialized key to a file.
    """
    keys_dir = "keys"
    os.makedirs(keys_dir, exist_ok=True)

    full_path = os.path.join(keys_dir, filename)

    with open(full_path, "wb") as f:
        f.write(key)


def load_key_from_file(filename):
    """
    Load a serialized key from a file.
    """
    keys_dir = "keys"

    full_path = os.path.join(keys_dir, filename)

    if not os.path.exists(full_path):
        raise FileNotFoundError(f"{filename} does not exist.")
    with open(full_path, "rb") as f:
        return f.read()


def fetch_diffie_hellman_params(server_url):
    """
    Fetches the Diffie-Hellman parameters from the server.
    """
    response = requests.get(f"{server_url}/auth/diffie-hellman-params")
    response.raise_for_status()

    if response.status_code == 200:
        params = response.json()
        return params.get("generator"), params.get("prime")
    else:
        raise Exception("Failed to fetch Diffie-Hellman parameters from the server.")


def generate_diffie_hellman_keys(generator, prime):
    """
    Generates Diffie-Hellman public and private keys.
    """
    dh_params = dh.DHParameterNumbers(int(prime), int(generator)).parameters(default_backend())
    private_key = dh_params.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key


def generate_rsa_keys():
    """
    Generates an RSA private and public key pair..
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_key(key, is_private=False):
    """
    Serializes a private or public key.
    """
    if is_private:
        return key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
    else:
        return key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        )


def register_user(server_url, email, password, dh_public_key, rsa_public_key):
    """
    Sends a registration request to the server.
    """
    payload = {
        "email": email,
        "password": password,
        "diffieHellmanExchangeKey": dh_public_key.decode(),
        "rsaPublicKey": rsa_public_key.decode(),
    }

    response = requests.post(f"{server_url}/auth/register", json=payload)

    if response.status_code == 200:
        print(f"Registration successful for {email}.")
        return response.json()
    else:
        raise Exception(f"Registration failed: {response.status_code}, {response.json().get('message')}")


def login_user(server_url, email, password):
    """
    Sends a login request to the server.
    """
    payload = {
        "email": email,
        "password": password
    }

    response = requests.post(f"{server_url}/auth/login", json=payload)

    if response.status_code == 200:
        print(f"Login successful for {email}.")
        return response.json()
    else:
        raise Exception(f"Login failed: {response.status_code}, {response.text}")


def check_recipient_exists(server_url, headers, recipient_email):
    """
    Checks if the recipient's account exists on the server.
    """
    response = requests.get(f"{server_url}/email/checkEmailAndGetDiffieHellmanInfo?email={recipient_email}",
                            headers=headers)

    if response.status_code == 200:
        recipient_info = response.json()
        recipient_dh_public_key = recipient_info['diffieHellmanExchangeKey']

        return recipient_dh_public_key.encode('utf-8')
    else:
        raise Exception(f"Recipient not found: {response.status_code}, {response.json()}")


def compute_shared_secret(dh_private_key, recipient_dh_public_key) -> bytes:
    """
    Computes the shared secret using the client's private Diffie-Hellman key and the recipient's public Diffie-Hellman key.
    """
    if isinstance(recipient_dh_public_key, bytes):
        recipient_dh_public_key = serialization.load_pem_public_key(recipient_dh_public_key, backend=default_backend())

    if isinstance(dh_private_key, bytes):
        dh_private_key = serialization.load_pem_private_key(dh_private_key, password=None, backend=default_backend())

    shared_secret = dh_private_key.exchange(recipient_dh_public_key)
    return shared_secret


def create_aes_key(shared_secret: bytes) -> bytes:
    return hashlib.sha256(shared_secret).digest()


def encrypt_message(plaintext: str, shared_secret_key: bytes) -> bytes:
    # Ensure the shared secret key is 32 bytes (256 bits) for AES-256
    if len(shared_secret_key) != 32:
        raise ValueError("The shared secret key must be 32 bytes for AES-256.")

    # Generate a random Initialization Vector (IV)
    iv = os.urandom(16)

    # Create a Cipher object
    cipher = Cipher(algorithms.AES(shared_secret_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the plaintext to be a multiple of the block size (16 bytes for AES)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    # Encrypt the data
    encrypted_message = encryptor.update(padded_data) + encryptor.finalize()

    # Return the IV concatenated with the encrypted message
    return iv + encrypted_message


def decrypt_message(encrypted_message: bytes, shared_secret_key: bytes) -> str:
    # Ensure the shared secret key is 32 bytes (256 bits) for AES-256
    if len(shared_secret_key) != 32:
        raise ValueError("The shared secret key must be 32 bytes for AES-256.")

    # Extract the IV and the encrypted data
    iv = encrypted_message[:16]
    encrypted_data = encrypted_message[16:]

    # Create a Cipher object
    cipher = Cipher(algorithms.AES(shared_secret_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the data
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return plaintext.decode()


def sign_message(message: bytes, private_key) -> bytes:
    if isinstance(private_key, bytes):
        private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
    signature = private_key.sign(
        message,
        asymmetric_padding.PSS(
            mgf=asymmetric_padding.MGF1(hashes.SHA256()),
            salt_length=asymmetric_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(message: bytes, signature: bytes, public_key) -> bool:
    try:
        if isinstance(public_key, str):
            public_key = str.encode(public_key)
        if isinstance(public_key, bytes):
            public_key = serialization.load_pem_public_key(public_key, backend=default_backend())

        public_key.verify(
            signature,
            message,
            asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False


def send_email(server_url: str, headers, recipient_email, message: bytes, signature: bytes):
    message_str = convert_bytes_to_base64(message)
    signature_str = convert_bytes_to_base64(signature)

    payload = {
        "email": recipient_email,
        "message": message_str,
        "signature": signature_str
    }
    response = requests.post(
        f"{server_url}/email/sendEmailWithSignature",
        json=payload,
        headers=headers
    )
    if response.status_code != 200:
        raise Exception(response.json())
    else:
        print("Email sent successfully.")


def convert_bytes_to_base64(byte_array):
    return base64.b64encode(byte_array).decode('utf-8')


def convert_base64_to_bytes(base64_string):
    return base64.b64decode(base64_string)


def get_my_emails(server_url: str, headers):
    response = requests.get(f"{server_url}/email/getMyEmails", headers=headers)
    if response.status_code != 200:
        raise Exception(response.json())
    return response.json()


if __name__ == "__main__":
    main_menu()
