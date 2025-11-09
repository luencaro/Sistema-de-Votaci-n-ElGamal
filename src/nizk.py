"""Pruebas NIZK con Fiat-Shamir - Protocolo Sigma disjuntivo"""
import secrets
from collections import namedtuple
from elgamal import PublicKey, Ciphertext
from crypto_utils import hash_to_challenge, mod_inverse

NIZKProof = namedtuple('NIZKProof', ['a1_v', 'a1_e', 'a2_v', 'a2_e', 'z1', 'z2', 'c1', 'c2'])


class NIZKSystem:
    """Sistema de pruebas NIZK para validez de votos"""
    
    @staticmethod
    def generate_proof(vote_bit, ciphertext, randomness, public_key):
        """Genera prueba NIZK de que cifrado contiene 0 o 1"""
        p, q, g, u = public_key.p, public_key.q, public_key.g, public_key.u
        v, e = ciphertext.v, ciphertext.e
        
        if vote_bit == 0:
            return NIZKSystem._generate_proof_for_zero(v, e, randomness, p, q, g, u)
        else:
            return NIZKSystem._generate_proof_for_one(v, e, randomness, p, q, g, u)
    
    @staticmethod
    def _generate_proof_for_zero(v, e, beta, p, q, g, u):
        """Genera prueba cuando voto es 0 (rama real b=0, simulada b=1)"""
        w1 = secrets.randbelow(q - 1) + 1
        a1_v = pow(g, w1, p)
        a1_e = pow(u, w1, p)
        
        c2 = secrets.randbelow(q - 1) + 1
        z2 = secrets.randbelow(q - 1) + 1
        v_c2_inv = mod_inverse(pow(v, c2, p), p)
        a2_v = (pow(g, z2, p) * v_c2_inv) % p
        e_div_g = (e * mod_inverse(g, p)) % p
        e_div_g_c2_inv = mod_inverse(pow(e_div_g, c2, p), p)
        a2_e = (pow(u, z2, p) * e_div_g_c2_inv) % p
        
        c = hash_to_challenge(p, q, g, u, v, e, a1_v, a1_e, a2_v, a2_e) % q
        c1 = (c - c2) % q
        z1 = (w1 + c1 * beta) % q
        
        return NIZKProof(a1_v, a1_e, a2_v, a2_e, z1, z2, c1, c2)
    
    @staticmethod
    def _generate_proof_for_one(v, e, beta, p, q, g, u):
        """Genera prueba cuando voto es 1 (rama simulada b=0, real b=1)"""
        c1 = secrets.randbelow(q - 1) + 1
        z1 = secrets.randbelow(q - 1) + 1
        v_c1_inv = mod_inverse(pow(v, c1, p), p)
        a1_v = (pow(g, z1, p) * v_c1_inv) % p
        e_c1_inv = mod_inverse(pow(e, c1, p), p)
        a1_e = (pow(u, z1, p) * e_c1_inv) % p
        
        w2 = secrets.randbelow(q - 1) + 1
        a2_v = pow(g, w2, p)
        a2_e = pow(u, w2, p)
        
        c = hash_to_challenge(p, q, g, u, v, e, a1_v, a1_e, a2_v, a2_e) % q
        c2 = (c - c1) % q
        z2 = (w2 + c2 * beta) % q
        
        return NIZKProof(a1_v, a1_e, a2_v, a2_e, z1, z2, c1, c2)
    
    @staticmethod
    def verify_proof(ciphertext, proof, public_key):
        """Verifica prueba NIZK de validez de voto"""
        p, q, g, u = public_key.p, public_key.q, public_key.g, public_key.u
        v, e = ciphertext.v, ciphertext.e
        
        c = hash_to_challenge(p, q, g, u, v, e, proof.a1_v, proof.a1_e, proof.a2_v, proof.a2_e) % q
        
        if (proof.c1 + proof.c2) % q != c:
            print("  ✗ Verificación falló: c1 + c2 ≠ c")
            return False
        
        # Rama 1 (b=0)
        if pow(g, proof.z1, p) != (proof.a1_v * pow(v, proof.c1, p)) % p:
            print("  ✗ Verificación falló en rama 1 (v)")
            return False
        if pow(u, proof.z1, p) != (proof.a1_e * pow(e, proof.c1, p)) % p:
            print("  ✗ Verificación falló en rama 1 (e)")
            return False
        
        # Rama 2 (b=1)
        if pow(g, proof.z2, p) != (proof.a2_v * pow(v, proof.c2, p)) % p:
            print("  ✗ Verificación falló en rama 2 (v)")
            return False
        
        e_div_g = (e * mod_inverse(g, p)) % p
        if pow(u, proof.z2, p) != (proof.a2_e * pow(e_div_g, proof.c2, p)) % p:
            print("  ✗ Verificación falló en rama 2 (e/g)")
            return False
        
        return True
