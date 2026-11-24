
import os
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature, InvalidTag

print("=== CHECKPOINT 3: SECURE FILE SHARING ===")

alice = x25519.X25519PrivateKey.generate()
bob = x25519.X25519PrivateKey.generate()

identitas_bob = ed25519.Ed25519PrivateKey.generate()
publik_bob = bob.public_key().public_bytes_raw()
signature = identitas_bob.sign(publik_bob)

try:
    identitas_bob.public_key().verify(signature, publik_bob)
    print("Identitas Bob: VALID")
except InvalidSignature:
    print("Identitas Bob: TIDAK VALID")
    raise SystemExit

secret_A = alice.exchange(bob.public_key())
secret_B = bob.exchange(alice.public_key())
print("Shared secret sama:", secret_A == secret_B)

def buat_kunci(secret):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"checkpoint3"
    ).derive(secret)

kunci_A = buat_kunci(secret_A)
kunci_B = buat_kunci(secret_B)
print("Kunci sesi sama:", kunci_A == kunci_B)

mac = hmac.new(kunci_A, b"konfirmasi", hashlib.sha256).digest()
cek = hmac.new(kunci_B, b"konfirmasi", hashlib.sha256).digest()
print("Konfirmasi HMAC:", hmac.compare_digest(mac, cek))

file = b"Dokumen rahasia untuk Bob"
nonce = os.urandom(12)
ciphertext = AESGCM(kunci_A).encrypt(nonce, file, None)

hasil = AESGCM(kunci_B).decrypt(nonce, ciphertext, None)
print("File diterima:", hasil.decode())

eve = x25519.X25519PrivateKey.generate()

try:
    identitas_bob.public_key().verify(
        signature, eve.public_key().public_bytes_raw()
    )
    print("MITM: BERHASIL")
except InvalidSignature:
    print("MITM: DITOLAK")

data_rusak = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]

try:
    AESGCM(kunci_B).decrypt(nonce, data_rusak, None)
except InvalidTag:
    print("Perubahan data: DITOLAK")

pesan_diterima = set()
nomor_pesan = 1

for percobaan in range(2):
    if nomor_pesan in pesan_diterima:
        print("Replay attack: DITOLAK")
    else:
        pesan_diterima.add(nomor_pesan)
        print("Pesan pertama: DITERIMA")
