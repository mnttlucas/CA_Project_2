from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography import x509
from cryptography.x509 import NameOID
from cryptography.x509.oid import NameOID

from datetime import datetime, timedelta

import hashlib
import json
import os
import sys
import time

DCC_ISSUER_PRIVATE_KEY = "ISSUER/private_key.pem"
DCC_ISSUER_PUBLIC_KEY = "ISSUER/public_key.pem"
DCC_ISSUER_CERTIFICATE = "ISSUER/certificate.pem"

def generate_self_signed_certificate(private_key):
	subject = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"), x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Aveiro"), x509.NameAttribute(NameOID.LOCALITY_NAME, "Aveiro"), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Issuer Organization"), x509.NameAttribute(NameOID.COMMON_NAME, "Issuer Self-Signed Certificate")])
	issuer = subject
	certificate = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(private_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.utcnow()).not_valid_after(datetime.utcnow() + timedelta(days=365)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(private_key, hashes.SHA256(), default_backend())
	with open(DCC_ISSUER_CERTIFICATE, "wb") as f:
		f.write(certificate.public_bytes(serialization.Encoding.PEM))
	return certificate

def generate_issuer_key_pair():
	# Keys and certificate already exists, we load them
	if os.path.exists(DCC_ISSUER_PRIVATE_KEY) and os.path.exists(DCC_ISSUER_PUBLIC_KEY) and os.path.exists(DCC_ISSUER_CERTIFICATE):
		with open(DCC_ISSUER_PRIVATE_KEY, "rb") as f:
			private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
		with open(DCC_ISSUER_PUBLIC_KEY, "rb") as f:
			public_key = serialization.load_pem_public_key(f.read())
	# If any of them doesn't exist, we (re)generate them
	else:
		private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
		public_key = private_key.public_key()
		with open(DCC_ISSUER_PRIVATE_KEY, "wb") as f:
			f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))
		with open(DCC_ISSUER_PUBLIC_KEY, "wb") as f:
			f.write(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
		generate_self_signed_certificate(private_key)
	return private_key, public_key

def sign_dcc(fields_to_sign, private_key):
	serialized_data = json.dumps(fields_to_sign, sort_keys=True).encode()
	signature = private_key.sign(serialized_data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
	return signature.hex()

def compute_commitment(attribute_name, attribute_value, mask):
	return hashlib.sha256(f"{attribute_name}:{attribute_value}".encode() + mask).hexdigest()

def generate_dcc(request_file, output_file):
	# Load the DCC request file
	if not os.path.exists(request_file):
		print(f"[!] Request file '{request_file}' not found.")
		return
	with open(request_file, "r") as f:
		request_data = json.load(f)
	# Ensures that some fields aren't missing
	required_fields = ["attributes", "digest_function", "public_key"]
	for field in required_fields:
		if field not in request_data:
			print(f"[!] Invalid request: Missing field '{field}'.")
			return
	private_key, public_key = generate_issuer_key_pair()
	with open(DCC_ISSUER_CERTIFICATE, "rb") as f:
		issuer_certificate = f.read().decode()
	commitment_values = {attr["name"]: compute_commitment(attr["name"], attr["value"], bytes.fromhex(attr["mask"])) for attr in request_data["attributes"]}
	dcc = {"attributes": [], "digest_function": request_data["digest_function"], "public_key": request_data["public_key"]}
	for attr in request_data["attributes"]:
		dcc["attributes"].append({"name": attr["name"], "value": attr["value"], "commitment": commitment_values[attr["name"]]})
	fields_to_sign = {"commitment_values": commitment_values, "public_key": dcc["public_key"]}
	dcc_signature = sign_dcc(fields_to_sign, private_key)
	dcc["issuer_signature"] = {"value": dcc_signature, "timestamp": time.time(), "algorithm": "RSA-PSS-SHA256", "certificate": issuer_certificate}
	with open(output_file, "w") as f:
		json.dump(dcc, f, indent=4)
	print(f"[+] DCC saved to {output_file}.")

def main():
	if len(sys.argv) != 3:
		print("[!] Usage :", sys.argv[0], "[DCC Request File] [Output DCC Name].")
		return
	generate_dcc(sys.argv[1], sys.argv[2])


if __name__ == "__main__":
	main()