"""Cifrado ElGamal multiplicativo"""
import secrets
from collections import namedtuple
from crypto_utils import generate_safe_prime, find_generator

PublicKey = namedtuple('PublicKey', ['p', 'q', 'g', 'u'])
PrivateKey = namedtuple('PrivateKey', ['alpha'])
Ciphertext = namedtuple('Ciphertext', ['v', 'e'])


class ElGamalSystem:
    """Sistema de cifrado ElGamal multiplicativo"""
    
    def __init__(self, bits=512):
        self.bits = bits
        self.public_key = None
        self.private_key = None
    
    def generate_keys(self):
        """Genera par de claves pública/privada"""
        print("\n" + "="*70)
        print("GENERACIÓN DE PARÁMETROS DEL SISTEMA ELGAMAL")
        print("="*70)
        
        p, q = generate_safe_prime(self.bits)
        g = find_generator(p, q)
        alpha = secrets.randbelow(q - 1) + 1
        u = pow(g, alpha, p)
        
        print(f"\nClave privada: α = {alpha}")
        print(f"Clave pública: u = g^α mod p = {u}")
        print("="*70)
        
        self.public_key = PublicKey(p, q, g, u)
        self.private_key = PrivateKey(alpha)
        return self.public_key, self.private_key
    
    def encrypt(self, message_bit, public_key=None):
        """Cifra un bit (0 o 1) usando ElGamal multiplicativo"""
        if message_bit not in [0, 1]:
            raise ValueError("El mensaje debe ser 0 o 1")
        
        pk = public_key or self.public_key
        if pk is None:
            raise ValueError("No hay clave pública disponible")
        
        beta = secrets.randbelow(pk.q - 1) + 1
        v = pow(pk.g, beta, pk.p)
        u_beta = pow(pk.u, beta, pk.p)
        g_b = pow(pk.g, message_bit, pk.p)
        e = (u_beta * g_b) % pk.p
        
        return Ciphertext(v, e), beta
    
    def decrypt(self, ciphertext, private_key=None):
        """Descifra texto cifrado ElGamal, retorna g^m mod p"""
        sk = private_key or self.private_key
        if sk is None:
            raise ValueError("No hay clave privada disponible")
        
        pk = self.public_key
        v_alpha = pow(ciphertext.v, sk.alpha, pk.p)
        
        from crypto_utils import mod_inverse
        v_alpha_inv = mod_inverse(v_alpha, pk.p)
        g_m = (ciphertext.e * v_alpha_inv) % pk.p
        return g_m
    
    def homomorphic_add(self, ciphertexts):
        """Suma homomórfica multiplicando componentes de cifrados"""
        if not ciphertexts:
            raise ValueError("La lista de cifrados está vacía")
        
        pk = self.public_key
        v_product = 1
        e_product = 1
        
        for ct in ciphertexts:
            v_product = (v_product * ct.v) % pk.p
            e_product = (e_product * ct.e) % pk.p
        
        return Ciphertext(v_product, e_product)
    
    def decrypt_sum(self, aggregated_ciphertext, max_sum):
        """Descifra cifrado agregado y recupera suma por búsqueda exhaustiva"""
        g_sum = self.decrypt(aggregated_ciphertext)
        from crypto_utils import discrete_log_small
        return discrete_log_small(self.public_key.g, g_sum, self.public_key.p, max_sum)
