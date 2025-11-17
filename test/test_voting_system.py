"""
Pruebas unitarias para el sistema de votación ElGamal
Ejecutar con: python -m pytest test_voting_system.py
O simplemente: python test_voting_system.py
"""

import sys
import os
import unittest

# Agregar el directorio src al path para imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from crypto_utils import is_prime, generate_safe_prime, find_generator, mod_inverse, discrete_log_small
from elgamal import ElGamalSystem
from nizk import NIZKSystem
from token_system import TokenSystem
from voting_system import VotingAuthority, Voter, VotingCenter
from mixnet import Mixnet
from auditoria import SistemaAuditoria


class TestCryptoUtils(unittest.TestCase):
    """Pruebas para utilidades criptográficas"""
    
    def test_is_prime(self):
        """Probar detección de primalidad"""
        # Primos conocidos
        self.assertTrue(is_prime(2))
        self.assertTrue(is_prime(3))
        self.assertTrue(is_prime(5))
        self.assertTrue(is_prime(17))
        self.assertTrue(is_prime(97))
        
        # No primos
        self.assertFalse(is_prime(1))
        self.assertFalse(is_prime(4))
        self.assertFalse(is_prime(15))
        self.assertFalse(is_prime(100))
    
    def test_safe_prime_generation(self):
        """Probar generación de primos seguros"""
        p, q = generate_safe_prime(bits=64)
        
        # Verificar que p = 2q + 1
        self.assertEqual(p, 2 * q + 1)
        
        # Verificar que ambos son primos
        self.assertTrue(is_prime(p))
        self.assertTrue(is_prime(q))
    
    def test_mod_inverse(self):
        """Probar inverso modular"""
        # 3 * 5 = 15 ≡ 1 (mod 7)
        # Entonces inv(3, 7) = 5
        self.assertEqual(mod_inverse(3, 7), 5)
        
        # Verificar propiedad: a * inv(a) ≡ 1 (mod m)
        a, m = 7, 26
        inv = mod_inverse(a, m)
        self.assertEqual((a * inv) % m, 1)
    
    def test_discrete_log_small(self):
        """Probar logaritmo discreto para valores pequeños"""
        p = 23
        g = 5
        
        # g^7 mod p
        h = pow(g, 7, p)
        x = discrete_log_small(g, h, p, max_value=20)
        
        self.assertEqual(x, 7)
        self.assertEqual(pow(g, x, p), h)


class TestElGamal(unittest.TestCase):
    """Pruebas para el sistema ElGamal"""
    
    def setUp(self):
        """Configurar sistema ElGamal para pruebas"""
        self.system = ElGamalSystem(bits=128)
        self.public_key, self.private_key = self.system.generate_keys()
    
    def test_encrypt_decrypt_zero(self):
        """Probar cifrado y descifrado de 0"""
        ciphertext, _ = self.system.encrypt(0)
        decrypted = self.system.decrypt(ciphertext)
        
        # Debe descifrar a g^0 = 1
        self.assertEqual(decrypted, 1)
    
    def test_encrypt_decrypt_one(self):
        """Probar cifrado y descifrado de 1"""
        ciphertext, _ = self.system.encrypt(1)
        decrypted = self.system.decrypt(ciphertext)
        
        # Debe descifrar a g^1 = g
        self.assertEqual(decrypted, self.public_key.g)
    
    def test_invalid_message(self):
        """Probar que se rechacen mensajes inválidos"""
        with self.assertRaises(ValueError):
            self.system.encrypt(2)
        
        with self.assertRaises(ValueError):
            self.system.encrypt(-1)
    
    def test_homomorphic_addition(self):
        """Probar propiedad homomórfica"""
        # Cifrar varios votos
        votes = [1, 0, 1, 1, 0, 1]  # suma = 4
        ciphertexts = []
        
        for vote in votes:
            ct, _ = self.system.encrypt(vote)
            ciphertexts.append(ct)
        
        # Acumular
        aggregated = self.system.homomorphic_add(ciphertexts)
        
        # Descifrar suma
        suma = self.system.decrypt_sum(aggregated, max_sum=len(votes))
        
        self.assertEqual(suma, sum(votes))
    
    def test_homomorphic_all_zeros(self):
        """Probar acumulación de solo ceros"""
        votes = [0, 0, 0, 0]
        ciphertexts = [self.system.encrypt(v)[0] for v in votes]
        
        aggregated = self.system.homomorphic_add(ciphertexts)
        suma = self.system.decrypt_sum(aggregated, max_sum=len(votes))
        
        self.assertEqual(suma, 0)
    
    def test_homomorphic_all_ones(self):
        """Probar acumulación de solo unos"""
        votes = [1, 1, 1, 1, 1]
        ciphertexts = [self.system.encrypt(v)[0] for v in votes]
        
        aggregated = self.system.homomorphic_add(ciphertexts)
        suma = self.system.decrypt_sum(aggregated, max_sum=len(votes))
        
        self.assertEqual(suma, 5)


class TestNIZK(unittest.TestCase):
    """Pruebas para el sistema NIZK"""
    
    def setUp(self):
        """Configurar sistema para pruebas NIZK"""
        self.system = ElGamalSystem(bits=128)
        self.public_key, _ = self.system.generate_keys()
    
    def test_nizk_proof_for_zero(self):
        """Probar generación y verificación de prueba para 0"""
        vote = 0
        ciphertext, randomness = self.system.encrypt(vote)
        
        proof = NIZKSystem.generate_proof(vote, ciphertext, randomness, self.public_key)
        is_valid = NIZKSystem.verify_proof(ciphertext, proof, self.public_key)
        
        self.assertTrue(is_valid)
    
    def test_nizk_proof_for_one(self):
        """Probar generación y verificación de prueba para 1"""
        vote = 1
        ciphertext, randomness = self.system.encrypt(vote)
        
        proof = NIZKSystem.generate_proof(vote, ciphertext, randomness, self.public_key)
        is_valid = NIZKSystem.verify_proof(ciphertext, proof, self.public_key)
        
        self.assertTrue(is_valid)
    
    def test_nizk_multiple_proofs(self):
        """Probar múltiples pruebas independientes"""
        for _ in range(10):
            vote = _ % 2  # Alternar entre 0 y 1
            ciphertext, randomness = self.system.encrypt(vote)
            
            proof = NIZKSystem.generate_proof(vote, ciphertext, randomness, self.public_key)
            is_valid = NIZKSystem.verify_proof(ciphertext, proof, self.public_key)
            
            self.assertTrue(is_valid)


class TestTokenSystem(unittest.TestCase):
    """Pruebas para el sistema de tokens"""
    
    def setUp(self):
        """Configurar sistema de tokens"""
        self.token_system = TokenSystem()
    
    def test_issue_token(self):
        """Probar emisión de token"""
        token = self.token_system.issue_token("Alice")
        
        self.assertEqual(token.voter_id, "Alice")
        self.assertIsNotNone(token.token)
        self.assertIsNotNone(token.issued_at)
    
    def test_verify_valid_token(self):
        """Probar verificación de token válido"""
        token = self.token_system.issue_token("Bob")
        
        is_valid, msg = self.token_system.verify_token(token.token)
        
        self.assertTrue(is_valid)
        self.assertEqual(msg, "Token válido")
    
    def test_verify_invalid_token(self):
        """Probar verificación de token inválido"""
        is_valid, msg = self.token_system.verify_token("fake_token")
        
        self.assertFalse(is_valid)
    
    def test_double_voting_prevention(self):
        """Probar prevención de voto doble"""
        token = self.token_system.issue_token("Charlie")
        
        # Primera verificación: válida
        is_valid, _ = self.token_system.verify_token(token.token)
        self.assertTrue(is_valid)
        
        # Marcar como usado
        self.token_system.mark_token_used(token.token)
        
        # Segunda verificación: inválida
        is_valid, msg = self.token_system.verify_token(token.token)
        self.assertFalse(is_valid)
        self.assertIn("utilizado", msg.lower())
    
    def test_duplicate_token_issuance(self):
        """Probar que no se pueden emitir tokens duplicados"""
        self.token_system.issue_token("Diana")
        
        with self.assertRaises(ValueError):
            self.token_system.issue_token("Diana")
    
    def test_voter_statistics(self):
        """Probar estadísticas de votantes"""
        # Emitir tokens
        for i in range(5):
            self.token_system.issue_token(f"Voter_{i}")
        
        self.assertEqual(self.token_system.get_voter_count(), 5)
        self.assertEqual(self.token_system.get_voted_count(), 0)
        self.assertEqual(self.token_system.get_remaining_voters(), 5)
        
        # Marcar algunos como usados
        token1 = self.token_system.issue_token("Extra_1").token
        token2 = self.token_system.issue_token("Extra_2").token
        
        self.token_system.mark_token_used(token1)
        self.token_system.mark_token_used(token2)
        
        self.assertEqual(self.token_system.get_voted_count(), 2)


class TestVotingSystem(unittest.TestCase):
    """Pruebas de integración para el sistema completo"""
    
    def setUp(self):
        """Configurar sistema de votación completo"""
        self.authority = VotingAuthority(bits=128)
        self.public_key = self.authority.setup_election()
        
        self.voter_ids = ["Alice", "Bob", "Charlie"]
        self.tokens = self.authority.register_voters(self.voter_ids)
        
        self.voting_center = VotingCenter(
            self.authority.token_system,
            self.public_key,
            self.authority.auditoria
        )
    
    def test_valid_vote_accepted(self):
        """Probar que se aceptan votos válidos"""
        voter = Voter("Alice", self.tokens["Alice"])
        encrypted_vote = voter.cast_vote(True, self.public_key)
        
        accepted = self.voting_center.receive_vote(encrypted_vote)
        
        self.assertTrue(accepted)
        self.assertEqual(len(self.voting_center.valid_votes), 1)
    
    def test_double_vote_rejected(self):
        """Probar que se rechacen votos dobles"""
        voter = Voter("Bob", self.tokens["Bob"])
        
        # Primer voto
        vote1 = voter.cast_vote(True, self.public_key)
        accepted1 = self.voting_center.receive_vote(vote1)
        self.assertTrue(accepted1)
        
        # Segundo voto (debe ser rechazado)
        vote2 = voter.cast_vote(False, self.public_key)
        accepted2 = self.voting_center.receive_vote(vote2)
        self.assertFalse(accepted2)
        
        # Solo debe haber un voto registrado
        self.assertEqual(len(self.voting_center.valid_votes), 1)
    
    def test_full_election_cycle(self):
        """Probar ciclo completo de elección"""
        # Todos votan
        votes = [
            ("Alice", True),
            ("Bob", False),
            ("Charlie", True)
        ]
        
        for voter_id, vote_choice in votes:
            voter = Voter(voter_id, self.tokens[voter_id])
            encrypted_vote = voter.cast_vote(vote_choice, self.public_key)
            self.voting_center.receive_vote(encrypted_vote)
        
        # Verificar todos fueron aceptados
        self.assertEqual(len(self.voting_center.valid_votes), 3)
        
        # Realizar recuento
        from voting_system import TallyingCenter
        tallying = TallyingCenter(self.authority.elgamal, self.authority.auditoria, self.public_key)
        
        valid_ciphertexts = self.voting_center.get_valid_votes()
        yes_count, no_count = tallying.tally_votes(valid_ciphertexts)
        
        # Verificar resultados
        self.assertEqual(yes_count, 2)  # Alice y Charlie votaron SÍ
        self.assertEqual(no_count, 1)   # Bob votó NO
        self.assertEqual(yes_count + no_count, 3)


class TestMixnet(unittest.TestCase):
    """Pruebas para el sistema de mezcla"""
    
    def test_shuffle_and_recrypt(self):
        """Probar mezcla y re-cifrado de votos"""
        # Setup
        elgamal = ElGamalSystem(bits=128)
        public_key, _ = elgamal.generate_keys()
        mixnet = Mixnet(public_key)
        
        # Crear votos cifrados
        votes = [
            elgamal.encrypt(0, public_key)[0],  # Solo el ciphertext, no el beta
            elgamal.encrypt(1, public_key)[0],
            elgamal.encrypt(1, public_key)[0]
        ]
        
        # Mezclar
        mixed_votes, proof = mixnet.shuffle_and_recrypt(votes)
        
        # Verificar
        self.assertEqual(len(mixed_votes), len(votes))
        self.assertTrue(mixnet.verify_mix(votes, mixed_votes, proof))
    
    def test_mix_verification(self):
        """Probar verificación de mezcla"""
        elgamal = ElGamalSystem(bits=128)
        public_key, _ = elgamal.generate_keys()
        mixnet = Mixnet(public_key)
        
        votes = [elgamal.encrypt(1, public_key)[0]]  # Solo el ciphertext
        mixed_votes, proof = mixnet.shuffle_and_recrypt(votes)
        
        self.assertTrue(mixnet.verify_mix(votes, mixed_votes, proof))


class TestAuditoria(unittest.TestCase):
    """Pruebas para el sistema de auditoría"""
    
    def test_registrar_evento(self):
        """Probar registro de eventos"""
        auditoria = SistemaAuditoria()
        
        hash1 = auditoria.registrar_evento('SETUP', {'test': 'data1'})
        hash2 = auditoria.registrar_evento('REGISTRO', {'test': 'data2'})
        
        self.assertEqual(len(auditoria.eventos), 2)
        self.assertNotEqual(hash1, hash2)
    
    def test_verificar_integridad(self):
        """Probar verificación de integridad"""
        auditoria = SistemaAuditoria()
        
        auditoria.registrar_evento('SETUP', {})
        auditoria.registrar_evento('VOTO', {})
        
        # Cadena íntegra
        self.assertTrue(auditoria.verificar_integridad())
    
    def test_cadena_eventos(self):
        """Probar cadena de eventos enlazados"""
        auditoria = SistemaAuditoria()
        
        auditoria.registrar_evento('EVENTO1', {})
        auditoria.registrar_evento('EVENTO2', {})
        auditoria.registrar_evento('EVENTO3', {})
        
        # Verificar que cada evento apunta al anterior
        for i in range(1, len(auditoria.eventos)):
            self.assertEqual(
                auditoria.eventos[i].hash_previo,
                auditoria.eventos[i-1].hash_actual
            )


def run_tests():
    """Ejecuta todas las pruebas"""
    # Crear suite de pruebas
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Agregar todas las clases de prueba
    suite.addTests(loader.loadTestsFromTestCase(TestCryptoUtils))
    suite.addTests(loader.loadTestsFromTestCase(TestElGamal))
    suite.addTests(loader.loadTestsFromTestCase(TestNIZK))
    suite.addTests(loader.loadTestsFromTestCase(TestTokenSystem))
    suite.addTests(loader.loadTestsFromTestCase(TestVotingSystem))
    suite.addTests(loader.loadTestsFromTestCase(TestMixnet))
    suite.addTests(loader.loadTestsFromTestCase(TestAuditoria))
    
    # Ejecutar pruebas
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Mostrar resumen
    print("\n" + "="*70)
    print("RESUMEN DE PRUEBAS")
    print("="*70)
    print(f"Pruebas ejecutadas: {result.testsRun}")
    print(f"Exitosas: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Fallos: {len(result.failures)}")
    print(f"Errores: {len(result.errors)}")
    print("="*70)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    import sys
    success = run_tests()
    sys.exit(0 if success else 1)
