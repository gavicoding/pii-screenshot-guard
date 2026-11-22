import unittest

from pii_guard.validators import (
    is_rfc1918_ipv4,
    is_valid_cnpj,
    is_valid_cpf,
    is_valid_luhn,
)


class TestValidators(unittest.TestCase):
    def test_valid_and_invalid_cpf(self):
        self.assertTrue(is_valid_cpf("529.982.247-25"))
        self.assertTrue(is_valid_cpf("52998224725"))
        self.assertFalse(is_valid_cpf("529.982.247-20"))
        self.assertFalse(is_valid_cpf("111.111.111-11"))
        self.assertFalse(is_valid_cpf("1234567890"))

    def test_valid_and_invalid_cnpj(self):
        self.assertTrue(is_valid_cnpj("11.222.333/0001-81"))
        self.assertFalse(is_valid_cnpj("11.222.333/0001-80"))
        self.assertFalse(is_valid_cnpj("00.000.000/0000-00"))

    def test_valid_and_invalid_luhn(self):
        self.assertTrue(is_valid_luhn("4242-4242-4242-4242"))
        self.assertTrue(is_valid_luhn("4242424242424242"))
        self.assertFalse(is_valid_luhn("4242-4242-4242-4241"))
        self.assertFalse(is_valid_luhn("1111111111111111"))

    def test_rfc1918_ipv4(self):
        self.assertTrue(is_rfc1918_ipv4("10.0.12.4"))
        self.assertTrue(is_rfc1918_ipv4("172.16.0.1"))
        self.assertTrue(is_rfc1918_ipv4("172.31.255.254"))
        self.assertTrue(is_rfc1918_ipv4("192.168.1.50"))
        self.assertFalse(is_rfc1918_ipv4("172.32.0.1"))
        self.assertFalse(is_rfc1918_ipv4("8.8.8.8"))
        self.assertFalse(is_rfc1918_ipv4("999.168.1.1"))


if __name__ == "__main__":
    unittest.main()
