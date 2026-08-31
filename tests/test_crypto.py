from app.core.crypto import crypto_service, mask_sensitive_value


def test_sensitive_values_are_encrypted_and_masked():
    plaintext = "sk-live-1234567890abcdef"
    ciphertext = crypto_service.encrypt(plaintext)
    assert plaintext not in ciphertext
    assert crypto_service.decrypt(ciphertext) == plaintext
    assert mask_sensitive_value(plaintext, "api_key") == "sk-l••••••cdef"
    assert mask_sensitive_value("password123", "password") == "pa••••••23"
    assert mask_sensitive_value("short", "token") == "••••••••"
