"""
Verification tests
"""

import codecs
import unittest
from tempfile import NamedTemporaryFile

from keys_generation import (generate_keys, certificate_x509_build, x509_certificate_write_to_file,
                             private_key_write_to_file, public_key_write_to_file)
from sberbank_tools import verify_signature, params_string_to_dict, params_get_checksum
from signature import (private_key_import_from_file, private_key_sign_message,
                       public_key_import_from_x509_certificate_string, public_key_import_from_x509_certificate_file)


class VerificationTests(unittest.TestCase):

    def test_documentation_java_example(self):
        # certificate
        certificate_string = (
            '-----BEGIN CERTIFICATE-----\n'
            "MIICcTCCAdqgAwIBAgIGAWAnZt3aMA0GCSqGSIb3DQEBCwUAMHwxIDAeBgkqhkiG9w0BCQEWEWt6"
            "bnRlc3RAeWFuZGV4LnJ1MQswCQYDVQQGEwJSVTESMBAGA1UECBMJVGF0YXJzdGFuMQ4wDAYDVQQH"
            "EwVLYXphbjEMMAoGA1UEChMDUkJTMQswCQYDVQQLEwJRQTEMMAoGA1UEAxMDUkJTMB4XDTE3MTIw"
            "NTE2MDEyMFoXDTE4MTIwNTE2MDExOVowfDEgMB4GCSqGSIb3DQEJARYRa3pudGVzdEB5YW5kZXgu"
            "cnUxCzAJBgNVBAYTAlJVMRIwEAYDVQQIEwlUYXRhcnN0YW4xDjAMBgNVBAcTBUthemFuMQwwCgYD"
            "VQQKEwNSQlMxCzAJBgNVBAsTAlFBMQwwCgYDVQQDEwNSQlMwgZ8wDQYJKoZIhvcNAQEBBQADgY0A"
            "MIGJAoGBAJNgxgtWRFe8zhF6FE1C8s1t/dnnC8qzNN+uuUOQ3hBx1CHKQTEtZFTiCbNLMNkgWtJ/"
            "CRBBiFXQbyza0/Ks7FRgSD52qFYUV05zRjLLoEyzG6LAfihJwTEPddNxBNvCxqdBeVdDThG81zC0"
            "DiAhMeSwvcPCtejaDDSEYcQBLLhDAgMBAAEwDQYJKoZIhvcNAQELBQADgYEAfRP54xwuGLW/Cg08"
            "ar6YqhdFNGq5TgXMBvQGQfRvL7W6oH67PcvzgvzN8XCL56dcpB7S8ek6NGYfPQ4K2zhgxhxpFEDH"
            "PcgU4vswnhhWbGVMoVgmTA0hEkwq86CA5ZXJkJm6f3E/J6lYoPQaKatKF24706T6iH2htG4Bkjre"
            "gUA=\n"
            '-----END CERTIFICATE-----'
        )
        # request params
        params = ("amount=35000099&sign_alias=SHA-256 with RSA&checksum="
                  "163BD9FAE437B5DCDAAC4EB5ECEE5E533DAC7BD2C8947B0719F7A8BD17C101EBDBEACDB295C10BF041E903"
                  "AF3FF1E6101FF7DB9BD024C6272912D86382090D5A7614E174DC034EBBB541435C80869CEED1F1E1710B71"
                  "D6EE7F52AE354505A83A1E279FBA02572DC4661C1D75ABF5A7130B70306CAFA69DABC2F6200A698198F8"
                  "&mdOrder=12b59da8-f68f-7c8d-12b5-9da8000826ea&operation=deposited&status=1")

        public_key = public_key_import_from_x509_certificate_string(certificate_string)
        params = params_string_to_dict(params)
        signature = params_get_checksum(params)

        self.assertTrue(verify_signature(public_key, signature, params))

    def test_all_steps(self):
        password = b'1234567812345678'
        private_key_file = NamedTemporaryFile(suffix='.pem').name
        public_key_file = NamedTemporaryFile(suffix='.pem').name
        certificate_file = NamedTemporaryFile(suffix='.cer').name

        # generate private and public keys
        private_key, public_key = generate_keys()
        # get x.509 certificate
        certificate = certificate_x509_build(private_key, public_key)

        # save keys and certificate to files
        private_key_write_to_file(private_key, private_key_file, password=password)
        public_key_write_to_file(public_key, public_key_file)
        x509_certificate_write_to_file(certificate, certificate_file)

        # import keys from files
        private_key = private_key_import_from_file(private_key_file, password=password)
        # import public key from x.509 certificate (because Sberbank gives certificate, not public key itself)
        public_key = public_key_import_from_x509_certificate_file(certificate_file)

        # some hypothetical data
        message = (b'mdOrder;a40330ae-8251-7d67-a505-8e6e5e3a9490;operation;deposited;'
                   b'orderNumber;1234-1234-1237;status;1;')

        # sign message with private key
        signature = private_key_sign_message(private_key, message)
        signature = codecs.encode(signature, 'hex').upper()

        # webhook request params
        params = f'orderNumber=1234-1234-1237&mdOrder=a40330ae-8251-7d67-a505-8e6e5e3a9490' \
                 f'&operation=deposited&status=1&checksum={signature.decode()}'
        # getting dictionary from params
        params = params_string_to_dict(params)
        # get signature from params
        signature = params_get_checksum(params)

        # verify signature with public key
        self.assertTrue(verify_signature(public_key, signature, params))


if __name__ == '__main__':
    unittest.main()
