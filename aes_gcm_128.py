from datetime import datetime

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def log_to_file(data: str):
    with open("log.txt", "a") as f:
        f.write(data + "\n")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    - Max length of result is same as length of "a"
    - If length of "b" is smaller than length of "a" then xor will be performed only on left part. For example:\n
        a = 0110\n
        b = 10\n
        result = 11
    """
    return bytes(x ^ y for x, y in zip(a, b))


def aes_encrypt(bytes_data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(bytes_data)


def gf_2_128_mul(x: int, y: int):
    assert x < (1 << 128)
    assert y < (1 << 128)

    R = 0xE1000000000000000000000000000000  # Irreducible polynomial for GF(2¹²⁸)
    z = 0
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= y
        if y & 1:
            y = (y >> 1) ^ R
        else:
            y >>= 1
    return z


def get_ghash(h: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    def padding_data():
        nonlocal data
        if len(data) % 16 != 0:
            data += b"\x00" * (16 - len(data) % 16)

    len_aad = (len(aad) * 8).to_bytes(8, "big")
    len_ct = (len(ciphertext) * 8).to_bytes(8, "big")

    # Merge (in order) aad + pad, ciphertext + pad and bit lengths of aad and ct in 8 bytes representation
    data = aad
    padding_data()
    data += ciphertext
    padding_data()
    data += len_aad + len_ct

    ghash = 0
    # If data length is 16 then data contains only
    # 8 bytes of aad length (which is zero) and 8 bytes of ct length (which is zero too)
    # so in that case ghash must be 0
    if len(data) != 16:
        for i in range(0, len(data), 16):
            # Y_i+1 = (Y_i XOR data_i) * H
            # Y is ghash, data_i is one of the 16-bytes blocks
            ghash ^= int.from_bytes(data[i:i + 16], "big")
            ghash = gf_2_128_mul(ghash, int.from_bytes(h))

    return ghash.to_bytes(16, "big")


def encrypt_gcm(plaintext: bytes, key: bytes, aad: bytes = b"", nonce: bytes = None):
    log_to_file("==================== Start ENCRYPTION ====================")
    try:
        # nonce can be set in outer scope i.e. for testing
        if nonce is None:
            nonce = get_random_bytes(12)
        if len(nonce) != 12:
            raise ValueError(f"nonce length must be 12, input={nonce}")

        # Length of plaintext must be multiple of 16
        if len(plaintext) % 16 != 0:
            plaintext = pad(plaintext, 16)

        # Split plaintext in 16-bytes blocks to encrypt
        blocks = [plaintext[i:i + 16] for i in range(0, len(plaintext), 16)]
        ciphertext_blocks = []
        for i, block in enumerate(blocks, start=2):
            counter = nonce + i.to_bytes(4, 'big')
            encrypted_counter = aes_encrypt(counter, key)
            ciphertext_blocks.append(xor_bytes(block, encrypted_counter))
        ciphertext = b"".join(ciphertext_blocks) # Merge encrypted blocks into one piece

        h = aes_encrypt(b"\x00" * 16, key) # Root authentication key, H = E_key(0)
        ghash = get_ghash(h, aad, ciphertext)
        initial_counter = nonce + b"\x00\x00\x00\x01"
        encrypted_initial_counter = aes_encrypt(initial_counter, key)
        tag = xor_bytes(encrypted_initial_counter, ghash)

        log_to_file(
            f"Nonce: {nonce.hex()}\n"
            f"Original text (with pad): {plaintext.hex()}\n"
            f"Ciphertext: {ciphertext.hex()}\n"
            f"Tag: {tag.hex()}"
        )

    except Exception as err:
        log_to_file(str(err))
        raise err
    finally:
        log_to_file("====================  END  ENCRYPTION ====================\n")

    return ciphertext, nonce, tag


def decrypt_gcm(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    """
    It can never return None. It either returns bytes or raises an error.
    """
    log_to_file("==================== Start DECRYPTION ====================")
    try:
        if len(nonce) != 12:
            raise ValueError(f"nonce length must be 12, input={nonce}")

        h = aes_encrypt(b"\x00" * 16, key) # Root authentication key, H = E_key(0)
        ghash = get_ghash(h, aad, ciphertext)
        initial_counter = nonce + b"\x00\x00\x00\x01"
        encrypted_initial_counter = aes_encrypt(initial_counter, key)
        computed_tag = xor_bytes(encrypted_initial_counter, ghash)
        if computed_tag != tag:
            raise ValueError(f"Authentication failed! Computed tag: {computed_tag}")

        # Split ciphertext in 16-bytes blocks to decrypt
        blocks = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]
        plaintext_blocks = []
        for i, block in enumerate(blocks, start=2):
            counter = nonce + i.to_bytes(4, 'big')
            encrypted_counter = aes_encrypt(counter, key)
            plaintext_blocks.append(xor_bytes(block, encrypted_counter))
        plaintext = b""
        if plaintext_blocks:
            plaintext = b"".join(plaintext_blocks) # Merge decrypted blocks into one piece
            try:
                plaintext = unpad(plaintext, 16) # Unpad if needed
            except ValueError:
                # There was no padding - just pass
                pass

        if plaintext:
            log_to_file(f"Decrypted Text: {plaintext.hex()}")

    except Exception as err:
        log_to_file(str(err))
        raise err
    finally:
        log_to_file("====================  END  DECRYPTION ====================\n")

    return plaintext


def test_nist_vectors_encryption():
    test_vectors = [
        {
            "count": 1,
            "name": "Encrypt only [key, nonce]",
            "key": bytes.fromhex("11754cd72aec309bf52f7687212e8957"),
            "nonce": bytes.fromhex("3c819d9a9bed087615030b65"),
            "plaintext": b"",
            "aad": b"",
            "expected_ciphertext": b"",
            "expected_tag": bytes.fromhex("250327c674aaf477aef2675748cf6971")
        },
        {
            "count": 2,
            "name": "Encrypt only [key, nonce, plaintext]",
            "key": bytes.fromhex("7fddb57453c241d03efbed3ac44e371c"),
            "nonce": bytes.fromhex("ee283a3fc75575e33efd4887"),
            "plaintext": bytes.fromhex("d5de42b461646c255c87bd2962d3b9a2"),
            "aad": b"",
            "expected_ciphertext": bytes.fromhex("2ccda4a5415cb91e135c2a0f78c9b2fd"),
            "expected_tag": bytes.fromhex("b36d1df9b9d5e596f83e8b7f52971cb3")
        },
        {
            "count": 3,
            "name": "Encrypt all [key, nonce, plaintext, aad]",
            "key": bytes.fromhex("c939cc13397c1d37de6ae0e1cb7c423c"),
            "nonce": bytes.fromhex("b3d8cc017cbb89b39e0f67e2"),
            "plaintext": bytes.fromhex("c3b3c41f113a31b73d9a5cd432103069"),
            "aad": bytes.fromhex("24825602bd12a984e0092d3e448eda5f"),
            "expected_ciphertext": bytes.fromhex("93fe7d9e9bfd10348a5606e5cafa7354"),
            "expected_tag": bytes.fromhex("0032a1dc85f1c9786925a2e71d8272dd")
        },
    ]

    log_to_file("==================== NIST VECTORS ENCRYPTION BEGIN ====================\n")
    try:
        for vector in test_vectors:
            ciphertext, nonce, tag = encrypt_gcm(vector["plaintext"], vector["key"], vector["aad"], vector["nonce"])
            fail_msg = f'{vector["count"]} -- {vector["name"]} failed -- '
            assert ciphertext == vector["expected_ciphertext"], \
                fail_msg + f'ciphertext={ciphertext.hex()} -- expected={vector["expected_ciphertext"].hex()}'
            assert tag == vector["expected_tag"], \
                fail_msg + f'computed_tag={tag.hex()} -- expected={vector["expected_tag"].hex()}'

        success_msg = "NIST encryption test vectors passed successfully."
        log_to_file(success_msg)
        print(success_msg)

    except AssertionError as err:
        log_to_file(str(err))
        raise err
    finally:
        log_to_file("==================== NIST VECTORS ENCRYPTION  END  ====================\n")


def test_nist_vectors_decryption():
    test_vectors = [
        {
            "count": 1,
            "name": "Decrypt only [key, nonce]",
            "key": bytes.fromhex("cf063a34d4a9a76c2c86787d3f96db71"),
            "nonce": bytes.fromhex("113b9785971864c83b01c787"),
            "ciphertext": b"",
            "aad": b"",
            "tag": bytes.fromhex("72ac8493e3a5228b5d130a69d2510e42"),
            "expected_plaintext": b"",
        },
        {
            "count": 2,
            "name": "Decrypt only [key, nonce, ciphertext]",
            "key": bytes.fromhex("e98b72a9881a84ca6b76e0f43e68647a"),
            "nonce": bytes.fromhex("8b23299fde174053f3d652ba"),
            "ciphertext": bytes.fromhex("5a3c1cf1985dbb8bed818036fdd5ab42"),
            "aad": b"",
            "tag": bytes.fromhex("23c7ab0f952b7091cd324835043b5eb5"),
            "expected_plaintext": bytes.fromhex("28286a321293253c3e0aa2704a278032"),
        },
        {
            "count": 3,
            "name": "Decrypt all [key, nonce, ciphertext, aad]",
            "key": bytes.fromhex("816e39070410cf2184904da03ea5075a"),
            "nonce": bytes.fromhex("32c367a3362613b27fc3e67e"),
            "ciphertext": bytes.fromhex("552ebe012e7bcf90fcef712f8344e8f1"),
            "aad": bytes.fromhex("f2a30728ed874ee02983c294435d3c16"),
            "tag": bytes.fromhex("ecaae9fc68276a45ab0ca3cb9dd9539f"),
            "expected_plaintext": bytes.fromhex("ecafe96c67a1646744f1c891f5e69427"),
        },
    ]

    log_to_file("==================== NIST VECTORS DECRYPTION BEGIN ====================\n")
    try:
        for vector in test_vectors:
            fail_msg = f'{vector["count"]} -- {vector["name"]} failed -- '
            decrypted = decrypt_gcm(vector["ciphertext"], vector["key"], vector["nonce"], vector["tag"], vector["aad"])
            assert decrypted == vector["expected_plaintext"], \
                fail_msg + f'plaintext={decrypted.hex()} -- expected={vector["expected_plaintext"].hex()}'

        success_msg = "NIST decryption test vectors passed successfully."
        log_to_file(success_msg)
        print(success_msg)

    except AssertionError as err:
        log_to_file(str(err))
        raise err
    finally:
        log_to_file("==================== NIST VECTORS DECRYPTION  END  ====================\n")


def main():
    key = get_random_bytes(16) # Random 128-bit key in bytes
    plaintext = b"Lorem ipsum dolor sit amet" # Text to be encrypted
    aad = b"authentication data" # Authentication data

    ciphertext, nonce, tag = encrypt_gcm(plaintext, key, aad)
    print(
        f"Key: {key.hex()}\n"
        f"Plaintext: {plaintext}\n"
        f"Ciphertext: {ciphertext.hex()}\n"
        f"Nonce: {nonce.hex()}\n"
        f"Tag: {tag.hex()}"
    )

    decrypted = decrypt_gcm(ciphertext, key, nonce, tag, aad)
    print(f"Decrypted: {decrypted}")

    test_nist_vectors_encryption()
    test_nist_vectors_decryption()


if __name__ == '__main__':
    log_to_file(f"START LOG: {datetime.now().strftime("%d.%m.%Y - %H:%M:%S")}")
    try:
        main()
    finally:
        log_to_file(f"END LOG: {datetime.now().strftime("%d.%m.%Y - %H:%M:%S")}\n")
