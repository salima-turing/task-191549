import nfc
import ndef
from Cryptodome.Cipher import DES
from Cryptodome import Random

# NFC reader/writer configuration
clf = nfc.ContactlessFrontend('usb')


# Define a simple encryption/decryption function using DES
def encrypt_message(message, key):
    cipher = DES.new(key, DES.MODE_ECB)
    pad = lambda s: s + (8 - len(s) % 8) * chr(8 - len(s) % 8)
    padded_message = pad(message)
    encrypted_message = cipher.encrypt(padded_message.encode('utf-8'))
    return encrypted_message


def decrypt_message(encrypted_message, key):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_message = cipher.decrypt(encrypted_message).decode('utf-8')
    unpad = lambda s: s[:-ord(s[len(s) - 1:])]
    return unpad(decrypted_message)


# A secure key for encryption/decryption (should be securely stored)
key = b'Sixteen byte key'

# NFC message to be encrypted
message = "Hello, this is a secure NFC message!"

encrypted_message = encrypt_message(message, key)

# Prepare the NFC message using NDEF Record
record = ndef.UriRecord(u'encrypted://' + encrypted_message.hex())

# Write the encrypted message to an NFC tag
with clf:
    target = clf.sense(ndef.NfcTarget)

    if target is None:
        print("No NFC tag detected.")
    else:
        tag = nfc.tag.tt3.Type3Tag(clf, target)
        tag.ndef.records = [record]
        print("Message encrypted and written to NFC tag successfully!")

# Read the NFC tag and decrypt the message
with clf:
    target = clf.sense(ndef.NfcTarget)

    if target is None:
        print("No NFC tag detected.")
    else:
        tag = nfc.tag.tt3.Type3Tag(clf, target)
        records = tag.ndef.records

        if len(records) > 0:
            first_record = records[0]
            if first_record.type == 'urn:nfc:wkt:U':
                encrypted_data = first_record.uri[11:]  # Remove 'encrypted://' prefix
                decrypted_message = decrypt_message(bytes.fromhex(encrypted_data), key)
                print("Decrypted message:", decrypted_message)
            else:
                print("Invalid NFC record type.")
        else:
            print("No NDEF records found on the tag.")
