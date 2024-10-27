import nfc
import cryptography
from cryptography.fernet import Fernet

# Step 1: Generate a secure key for encryption/decryption
key = Fernet.generate_key()
cipher_suite = Fernet(key)

def encrypt_message(message: bytes) -> bytes:
	return cipher_suite.encrypt(message)

def decrypt_message(encrypted_message: bytes) -> bytes:
	return cipher_suite.decrypt(encrypted_message)

def read_nfc_tag():
	clf = nfc.ContactlessFrontend('usb')
	clf.open()

	target = clf.sense(nfc.clf.RemoteTarget('106A'))

	if target is None:
		print("No NFC tag detected.")
		return

	tag = nfc.tag.tt3.Type3Tag(clf, target)

	try:
		tag.connect()
		ndef = tag.ndef

		print("Reading NFC tag...")
		data = ndef.read()
		clf.close()
		return data

	except Exception as e:
		print(f"Error reading NFC tag: {e}")
		clf.close()
		return None

def write_nfc_tag(data: bytes):
	clf = nfc.ContactlessFrontend('usb')
	clf.open()

	target = clf.sense(nfc.clf.RemoteTarget('106A'))

	if target is None:
		print("No NFC tag detected.")
		return

	tag = nfc.tag.tt3.Type3Tag(clf, target)

	try:
		tag.connect()
		ndef = tag.ndef

		print("Writing to NFC tag...")
		ndef.write(data)
		clf.close()
		print("Data written successfully!")

	except Exception as e:
		print(f"Error writing to NFC tag: {e}")
		clf.close()


if __name__ == "__main__":
	import argparse

	parser = argparse.ArgumentParser(description='NFC Secure Message App')
	parser.add_argument('-e', '--encrypt', action='store_true', help='Encrypt and write message to NFC tag')
	parser.add_argument('-d', '--decrypt', action='store_true', help='Decrypt message from NFC tag and display')
	args = parser.parse_args()

	if args.encrypt:
		message = input("Enter message to encrypt: ").encode()
		encrypted_data = encrypt_message(message)
		write_nfc_tag(encrypted_data)

	elif args.decrypt:
		encrypted_data = read_nfc_tag()
		if encrypted_data:
			try:
				decrypted_message = decrypt_message(encrypted_data)
				print(f"Decrypted message: {decrypted_message.decode()}")
			except cryptography.fernet.InvalidToken:
				print("Error decrypting message. Invalid key or data.")

	else:
		parser.print_help()
