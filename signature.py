#!/usr/bin/env python

"""
Signature verification
"""

from binascii import a2b_base64

from Cryptodome.Hash import SHA512
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5 as PKCS
from Cryptodome.Util.asn1 import DerSequence


def get_public_key_from_file(file_name):
    with open(file_name) as f:
        pem = f.read()
    lines = pem.replace(" ", '').split()
    der = a2b_base64(''.join(lines[1:-1]))

    # Extract subjectPublicKeyInfo field from X.509 certificate (see RFC3280)
    cert = DerSequence()
    cert.decode(der)
    tbsCertificate = DerSequence()
    tbsCertificate.decode(cert[0])
    subjectPublicKeyInfo = tbsCertificate[6]

    # Initialize RSA key
    publicKey = RSA.importKey(subjectPublicKeyInfo)
    return publicKey.publickey()


def private_key_import_from_file(filename, password):
    key_file = open(filename, 'rb')
    return RSA.importKey(key_file.read(), passphrase=password)


def public_key_import_from_x509_certificate_file(file_name):
    with open(file_name) as key_file:
        certificate = key_file.read()
    return public_key_import_from_x509_certificate_string(certificate)


def public_key_import_from_x509_certificate_string(certificate_string):
    if certificate_string.find('-----BEGIN CERTIFICATE-----') \
            and not certificate_string.find('-----BEGIN CERTIFICATE-----\n') \
            and not certificate_string.find('-----BEGIN CERTIFICATE-----\r\n'):
        certificate_string = certificate_string.replace('-----BEGIN CERTIFICATE-----', '-----BEGIN CERTIFICATE-----\n')
    if certificate_string.find('\n-----END CERTIFICATE-----') \
            and not certificate_string.find('\n-----END CERTIFICATE-----') \
            and not certificate_string.find('\r\n-----END CERTIFICATE-----'):
        certificate_string = certificate_string.replace('-----END CERTIFICATE-----', '\n-----END CERTIFICATE-----')
    lines = certificate_string.replace(" ", '').split()
    der = a2b_base64(''.join(lines[1:-1]))

    # Extract subjectPublicKeyInfo field from X.509 certificate (see RFC3280)
    cert = DerSequence()
    cert.decode(der)
    tbs_certificate = DerSequence()
    tbs_certificate.decode(cert[0])
    subject_public_key_info = tbs_certificate[6]

    # Initialize RSA key
    public_key = RSA.importKey(subject_public_key_info)
    return public_key.publickey()


def private_key_sign_message(private_key, message):
    # RSA Signature Generation
    h = SHA512.new()
    h.update(message)
    signer = PKCS.new(private_key)
    return signer.sign(h)


def public_key_verify_signature(public_key, signature, message):
    # At the receiver side, verification can be done like using the public part of the RSA key:
    # RSA Signature Verification
    h = SHA512.new()
    h.update(message)
    verifier = PKCS.new(public_key)
    if verifier.verify(h, signature):
        return True
    else:
        return False
