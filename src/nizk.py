"""
Pruebas NIZK para Validez de Votos
Protocolo: Chaum-Pedersen Disjuntivo con Transformación Fiat-Shamir

Este módulo implementa el protocolo Chaum-Pedersen disjuntivo que permite probar
que un cifrado ElGamal contiene g^0 o g^1 sin revelar cuál. El protocolo es
convertido de interactivo a no-interactivo mediante la transformación Fiat-Shamir.
"""
import secrets
from collections import namedtuple
from elgamal import PublicKey, Ciphertext
from crypto_utils import hash_to_challenge, mod_inverse

NIZKProof = namedtuple('NIZKProof', ['a1_v', 'a1_e', 'a2_v', 'a2_e', 'z1', 'z2', 'c1', 'c2'])


class NIZKSystem:
    """
    Sistema de Pruebas NIZK usando Chaum-Pedersen Disjuntivo + Fiat-Shamir
    
    Genera y verifica pruebas de conocimiento cero no-interactivas que demuestran
    que un cifrado ElGamal contiene 0 o 1 sin revelar cuál de los dos valores.
    """
    
    @staticmethod
    def generate_proof(vote_bit, ciphertext, randomness, public_key):
        """
        Genera prueba NIZK usando protocolo Chaum-Pedersen disjuntivo con Fiat-Shamir
        
        Demuestra que el cifrado contiene g^0 o g^1 sin revelar cuál.
        Una rama (la del voto real) se genera honestamente, la otra se simula.
        
        Args:
            vote_bit: 0 o 1 (voto real)
            ciphertext: Cifrado ElGamal (v, e)
            randomness: β usado en el cifrado
            public_key: Clave pública del sistema
            
        Returns:
            NIZKProof con commitments, responses y challenges de ambas ramas
        """
        p, q, g, u = public_key.p, public_key.q, public_key.g, public_key.u
        v, e = ciphertext.v, ciphertext.e
        
        if vote_bit == 0:
            return NIZKSystem._generate_proof_for_zero(v, e, randomness, p, q, g, u)
        else:
            return NIZKSystem._generate_proof_for_one(v, e, randomness, p, q, g, u)
    
    @staticmethod
    def _generate_proof_for_zero(v, e, beta, p, q, g, u):
        """
        Chaum-Pedersen disjuntivo para voto b=0
        Rama 1 (b=0): REAL - genera commitments honestamente
        Rama 2 (b=1): SIMULADA - construida hacia atrás
        """
        # RAMA 1 (REAL): Commitments honestos para b=0
        w1 = secrets.randbelow(q - 1) + 1  # Aleatoriedad fresca
        a1_v = pow(g, w1, p)  # Commitment: g^w1
        a1_e = pow(u, w1, p)  # Commitment: u^w1
        
        # RAMA 2 (SIMULADA): Simular rama b=1 hacia atrás
        c2 = secrets.randbelow(q - 1) + 1  # Challenge simulado
        z2 = secrets.randbelow(q - 1) + 1  # Response simulado
        # Calcular commitments usando ecuaciones de verificación invertidas
        v_c2_inv = mod_inverse(pow(v, c2, p), p)
        a2_v = (pow(g, z2, p) * v_c2_inv) % p
        e_div_g = (e * mod_inverse(g, p)) % p
        e_div_g_c2_inv = mod_inverse(pow(e_div_g, c2, p), p)
        a2_e = (pow(u, z2, p) * e_div_g_c2_inv) % p
        
        # FIAT-SHAMIR: Challenge global mediante hash
        c = hash_to_challenge(p, q, g, u, v, e, a1_v, a1_e, a2_v, a2_e) % q
        c1 = (c - c2) % q  # Challenge de rama real
        z1 = (w1 + c1 * beta) % q  # Response de rama real
        
        return NIZKProof(a1_v, a1_e, a2_v, a2_e, z1, z2, c1, c2)
    
    @staticmethod
    def _generate_proof_for_one(v, e, beta, p, q, g, u):
        """
        Chaum-Pedersen disjuntivo para voto b=1
        Rama 1 (b=0): SIMULADA - construida hacia atrás
        Rama 2 (b=1): REAL - genera commitments honestamente
        """
        # RAMA 1 (SIMULADA): Simular rama b=0 hacia atrás
        c1 = secrets.randbelow(q - 1) + 1  # Challenge simulado
        z1 = secrets.randbelow(q - 1) + 1  # Response simulado
        # Calcular commitments usando ecuaciones de verificación invertidas
        v_c1_inv = mod_inverse(pow(v, c1, p), p)
        a1_v = (pow(g, z1, p) * v_c1_inv) % p
        e_c1_inv = mod_inverse(pow(e, c1, p), p)
        a1_e = (pow(u, z1, p) * e_c1_inv) % p
        
        # RAMA 2 (REAL): Commitments honestos para b=1
        w2 = secrets.randbelow(q - 1) + 1  # Aleatoriedad fresca
        a2_v = pow(g, w2, p)  # Commitment: g^w2
        a2_e = pow(u, w2, p)  # Commitment: u^w2
        
        # FIAT-SHAMIR: Challenge global mediante hash
        c = hash_to_challenge(p, q, g, u, v, e, a1_v, a1_e, a2_v, a2_e) % q
        c2 = (c - c1) % q  # Challenge de rama real
        z2 = (w2 + c2 * beta) % q  # Response de rama real
        
        return NIZKProof(a1_v, a1_e, a2_v, a2_e, z1, z2, c1, c2)
    
    @staticmethod
    def verify_proof(ciphertext, proof, public_key):
        """
        Verifica prueba Chaum-Pedersen disjuntiva con Fiat-Shamir
        
        Verifica que la prueba demuestra que el cifrado contiene g^0 o g^1
        sin conocer cuál. Ambas ramas deben verificar correctamente.
        
        Args:
            ciphertext: Cifrado ElGamal (v, e) a verificar
            proof: NIZKProof generada por el probador
            public_key: Clave pública del sistema
            
        Returns:
            True si la prueba es válida, False en caso contrario
        """
        p, q, g, u = public_key.p, public_key.q, public_key.g, public_key.u
        v, e = ciphertext.v, ciphertext.e
        
        # FIAT-SHAMIR: Recalcular challenge global
        c = hash_to_challenge(p, q, g, u, v, e, proof.a1_v, proof.a1_e, proof.a2_v, proof.a2_e) % q
        
        # Verificar que challenges suman al challenge global
        if (proof.c1 + proof.c2) % q != c:
            print("  ✗ Verificación falló: c1 + c2 ≠ c")
            return False
        
        # CHAUM-PEDERSEN: Verificar ecuaciones de rama 1 (b=0)
        # g^z1 = a1_v * v^c1 y u^z1 = a1_e * e^c1
        if pow(g, proof.z1, p) != (proof.a1_v * pow(v, proof.c1, p)) % p:
            print("  ✗ Verificación falló en rama 1 (v)")
            return False
        if pow(u, proof.z1, p) != (proof.a1_e * pow(e, proof.c1, p)) % p:
            print("  ✗ Verificación falló en rama 1 (e)")
            return False
        
        # CHAUM-PEDERSEN: Verificar ecuaciones de rama 2 (b=1)
        # g^z2 = a2_v * v^c2 y u^z2 = a2_e * (e/g)^c2
        if pow(g, proof.z2, p) != (proof.a2_v * pow(v, proof.c2, p)) % p:
            print("  ✗ Verificación falló en rama 2 (v)")
            return False
        
        e_div_g = (e * mod_inverse(g, p)) % p
        if pow(u, proof.z2, p) != (proof.a2_e * pow(e_div_g, proof.c2, p)) % p:
            print("  ✗ Verificación falló en rama 2 (e/g)")
            return False
        
        return True
