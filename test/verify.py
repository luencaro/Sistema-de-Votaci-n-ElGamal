#!/usr/bin/env python3
"""
Script de verificación rápida del sistema
Ejecuta pruebas básicas para confirmar que todo funciona correctamente
"""

import sys
import os
import time

# Agregar el directorio src al path para imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))


def test_imports():
    """Verifica que todos los módulos se pueden importar"""
    print("Verificando imports...", end=" ")
    try:
        import crypto_utils
        import elgamal
        import nizk
        import token_system
        import voting_system
        print("✓")
        return True
    except ImportError as e:
        print(f"✗\nError: {e}")
        return False


def test_crypto_utils():
    """Prueba básica de utilidades criptográficas"""
    print("Probando crypto_utils...", end=" ")
    try:
        from crypto_utils import is_prime, generate_safe_prime
        
        # Verificar primalidad
        assert is_prime(17)
        assert not is_prime(16)
        
        # Generar primo pequeño
        p, q = generate_safe_prime(bits=64)
        assert p == 2 * q + 1
        assert is_prime(p) and is_prime(q)
        
        print("✓")
        return True
    except Exception as e:
        print(f"✗\nError: {e}")
        return False


def test_elgamal():
    """Prueba básica del sistema ElGamal"""
    print("Probando ElGamal...", end=" ")
    try:
        from elgamal import ElGamalSystem
        
        system = ElGamalSystem(bits=128)
        system.generate_keys()
        
        # Cifrar y descifrar
        ct_0, _ = system.encrypt(0)
        ct_1, _ = system.encrypt(1)
        
        dec_0 = system.decrypt(ct_0)
        dec_1 = system.decrypt(ct_1)
        
        assert dec_0 == 1  # g^0 = 1
        assert dec_1 == system.public_key.g  # g^1 = g
        
        # Homomorfia
        votes = [1, 0, 1]
        cts = [system.encrypt(v)[0] for v in votes]
        agg = system.homomorphic_add(cts)
        suma = system.decrypt_sum(agg, max_sum=len(votes))
        
        assert suma == sum(votes)
        
        print("✓")
        return True
    except Exception as e:
        print(f"✗\nError: {e}")
        return False


def test_nizk():
    """Prueba básica de pruebas NIZK"""
    print("Probando NIZK...", end=" ")
    try:
        from elgamal import ElGamalSystem
        from nizk import NIZKSystem
        
        system = ElGamalSystem(bits=128)
        pk, _ = system.generate_keys()
        
        # Generar y verificar prueba para 0
        ct, rand = system.encrypt(0)
        proof = NIZKSystem.generate_proof(0, ct, rand, pk)
        assert NIZKSystem.verify_proof(ct, proof, pk)
        
        # Generar y verificar prueba para 1
        ct, rand = system.encrypt(1)
        proof = NIZKSystem.generate_proof(1, ct, rand, pk)
        assert NIZKSystem.verify_proof(ct, proof, pk)
        
        print("✓")
        return True
    except Exception as e:
        print(f"✗\nError: {e}")
        return False


def test_tokens():
    """Prueba básica del sistema de tokens"""
    print("Probando tokens...", end=" ")
    try:
        from token_system import TokenSystem
        
        ts = TokenSystem()
        
        # Emitir token
        token = ts.issue_token("Alice")
        assert token.voter_id == "Alice"
        
        # Verificar token válido
        valid, _ = ts.verify_token(token.token)
        assert valid
        
        # Marcar como usado
        ts.mark_token_used(token.token)
        
        # Verificar que no se puede reusar
        valid, _ = ts.verify_token(token.token)
        assert not valid
        
        print("✓")
        return True
    except Exception as e:
        print(f"✗\nError: {e}")
        return False


def test_voting_system():
    """Prueba básica del sistema completo"""
    print("Probando sistema de votación...", end=" ")
    try:
        from voting_system import VotingAuthority, Voter, VotingCenter, TallyingCenter
        
        authority = VotingAuthority(bits=128)
        pk = authority.setup_election()
        
        # Registrar votantes
        tokens = authority.register_voters(["Alice", "Bob"])
        
        # Centro de votación
        vc = VotingCenter(authority.token_system, pk)
        
        # Votar
        alice = Voter("Alice", tokens["Alice"])
        vote_alice = alice.cast_vote(True, pk)
        assert vc.receive_vote(vote_alice)
        
        bob = Voter("Bob", tokens["Bob"])
        vote_bob = bob.cast_vote(False, pk)
        assert vc.receive_vote(vote_bob)
        
        # Contar
        tc = TallyingCenter(authority.elgamal)
        yes, no = tc.tally_votes(vc.get_valid_votes())
        
        assert yes == 1
        assert no == 1
        
        print("✓")
        return True
    except Exception as e:
        print(f"✗\nError: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Ejecuta todas las verificaciones"""
    print("\n" + "="*70)
    print("VERIFICACIÓN RÁPIDA DEL SISTEMA DE VOTACIÓN ELGAMAL")
    print("="*70 + "\n")
    
    start_time = time.time()
    
    tests = [
        ("Imports", test_imports),
        ("Utilidades Criptográficas", test_crypto_utils),
        ("Cifrado ElGamal", test_elgamal),
        ("Pruebas NIZK", test_nizk),
        ("Sistema de Tokens", test_tokens),
        ("Sistema Completo", test_voting_system)
    ]
    
    results = []
    
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"Error crítico en {name}: {e}")
            results.append((name, False))
    
    elapsed = time.time() - start_time
    
    print("\n" + "="*70)
    print("RESUMEN DE VERIFICACIÓN")
    print("="*70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {name:<30} {status}")
    
    print("\n" + "-"*70)
    print(f"  Total: {passed}/{total} pruebas pasadas")
    print(f"  Tiempo: {elapsed:.2f} segundos")
    print("-"*70)
    
    if passed == total:
        print("\n✓ ¡Sistema verificado correctamente!")
        print("  Puedes ejecutar 'python3 main.py' para la demostración completa.")
        return 0
    else:
        print("\n✗ Algunas verificaciones fallaron.")
        print("  Por favor revisa los errores arriba.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
