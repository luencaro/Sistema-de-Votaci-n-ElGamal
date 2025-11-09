"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
Ejemplos de uso individual de los componentes del sistema de votación
Este archivo demuestra cómo usar cada módulo de forma independiente
"""

from crypto_utils import generate_safe_prime, find_generator, hash_to_challenge, discrete_log_small
from elgamal import ElGamalSystem, PublicKey, Ciphertext
from nizk import NIZKSystem
from token_system import TokenSystem


def ejemplo_1_generar_primos():
    """Ejemplo: Generar primos seguros"""
    print("\n" + "="*70)
    print("EJEMPLO 1: Generación de Primos Seguros")
    print("="*70)
    
    # Generar un primo seguro pequeño para demostración
    p, q = generate_safe_prime(bits=128)
    
    print(f"\nPrimo seguro generado:")
    print(f"  p = {p}")
    print(f"  q = {q}")
    print(f"  Verificación: 2q + 1 = {2*q + 1}")
    print(f"  p == 2q + 1: {p == 2*q + 1}")


def ejemplo_2_elgamal_basico():
    """Ejemplo: Cifrado y descifrado básico con ElGamal"""
    print("\n" + "="*70)
    print("EJEMPLO 2: Cifrado ElGamal Básico")
    print("="*70)
    
    # Crear sistema ElGamal
    system = ElGamalSystem(bits=256)
    public_key, private_key = system.generate_keys()
    
    # Cifrar un voto (1 = SÍ)
    print("\nCifrando voto: 1 (SÍ)")
    ciphertext, randomness = system.encrypt(1)
    print(f"  Cifrado= {ciphertext.v}")
    print(f"           e = {ciphertext.e}")
    
    # Descifrar
    decrypted = system.decrypt(ciphertext)
    print(f"\nDescifrado: g^m = {decrypted}")
    print(f"  Valor esperado g^1 = {public_key.g}")
    print(f"  Coincide: {decrypted == public_key.g}")


def ejemplo_3_homomorfia():
    """Ejemplo: Acumulación homomórfica de votos"""
    print("\n" + "="*70)
    print("EJEMPLO 3: Propiedad Homomórfica")
    print("="*70)
    
    # Crear sistema
    system = ElGamalSystem(bits=256)
    system.generate_keys()
    
    # Cifrar varios votos
    votos = [1, 0, 1, 1, 0]  # 3 SÍ, 2 NO
    print(f"\nVotos originales: {votos}")
    print(f"  Suma esperada: {sum(votos)}")
    
    ciphertexts = []
    for i, voto in enumerate(votos):
        ct, _ = system.encrypt(voto)
        ciphertexts.append(ct)
        print(f"  Voto {i+1} cifrado: (v={ct.v % 1000}..., e={ct.e % 1000}...)")
    
    # Acumular homomórficamente
    print("\nAcumulando votos...")
    aggregated = system.homomorphic_add(ciphertexts)
    
    # Descifrar suma
    suma = system.decrypt_sum(aggregated, max_sum=len(votos))
    print(f"\nSuma descifrada: {suma}")
    print(f"  Suma real: {sum(votos)}")
    print(f"  Coincide: {suma == sum(votos)}")


def ejemplo_4_nizk():
    """Ejemplo: Generación y verificación de pruebas NIZK"""
    print("\n" + "="*70)
    print("EJEMPLO 4: Pruebas NIZK de Validez")
    print("="*70)
    
    # Crear sistema
    system = ElGamalSystem(bits=256)
    public_key, _ = system.generate_keys()
    
    # Cifrar un voto válido (0)
    voto = 0
    print(f"\nGenerando prueba para voto: {voto}")
    ciphertext, randomness = system.encrypt(voto)
    
    # Generar prueba NIZK
    proof = NIZKSystem.generate_proof(voto, ciphertext, randomness, public_key)
    print("  ✓ Prueba NIZK generada")
    
    # Verificar prueba
    print("\nVerificando prueba...")
    is_valid = NIZKSystem.verify_proof(ciphertext, proof, public_key)
    print(f"  Prueba válida: {is_valid}")
    
    # Intentar con voto inválido (2)
    print("\n\nIntentando cifrar voto inválido (2)...")
    try:
        system.encrypt(2)
    except ValueError as e:
        print(f"  ✓ Sistema rechaza voto inválido: {e}")


def ejemplo_5_tokens():
    """Ejemplo: Sistema de tokens"""
    print("\n" + "="*70)
    print("EJEMPLO 5: Sistema de Tokens")
    print("="*70)
    
    # Crear sistema de tokens
    token_system = TokenSystem()
    
    # Emitir tokens
    print("\nEmitiendo tokens:")
    token1 = token_system.issue_token("Alice")
    token2 = token_system.issue_token("Bob")
    
    print(f"  Token Alice: {token1.token[:40]}...")
    print(f"  Token Bob: {token2.token[:40]}...")
    
    # Verificar token válido
    print("\nVerificando token de Alice...")
    valid, msg = token_system.verify_token(token1.token)
    print(f"  Válido: {valid}")
    print(f"  Mensaje: {msg}")
    
    # Usar token
    print("\nMarcando token de Alice como usado...")
    token_system.mark_token_used(token1.token)
    
    # Intentar reusar
    print("\nIntentando reusar token de Alice...")
    valid, msg = token_system.verify_token(token1.token)
    print(f"  Válido: {valid}")
    print(f"  Mensaje: {msg}")


def ejemplo_6_logaritmo_discreto():
    """Ejemplo: Recuperación de suma mediante logaritmo discreto"""
    print("\n" + "="*70)
    print("EJEMPLO 6: Logaritmo Discreto")
    print("="*70)
    
    # Usar números pequeños para demostración
    p = 23  # primo pequeño
    g = 5   # generador
    
    print(f"\nParámetros:")
    print(f"  p = {p} (primo)")
    print(f"  g = {g} (generador)")
    
    # Calcular g^x para varios x
    print(f"\nCalculando potencias de g:")
    for x in range(10):
        g_x = pow(g, x, p)
        print(f"  g^{x} = {g_x:2d} (mod {p})")
    
    # Recuperar logaritmo discreto
    print(f"\nRecuperando logaritmo discreto:")
    target = pow(g, 7, p)
    print(f"  Dado h = {target}, encontrar x tal que g^x = h")
    
    x = discrete_log_small(g, target, p, max_value=20)
    print(f"  Resultado= {x}")
    print(f"  Verificación: g^{x} = {pow(g, x, p)} = {target}")


def ejemplo_7_hash_fiat_shamir():
    """Ejemplo: Función hash para Fiat-Shamir"""
    print("\n" + "="*70)
    print("EJEMPLO 7: Hash Fiat-Shamir")
    print("="*70)
    
    # Hashear diferentes elementos
    elements = [12345, 67890, "context_string"]
    
    print(f"\nElementos a hashear: {elements}")
    
    challenge = hash_to_challenge(*elements)
    print(f"  Challenge (decimal): {challenge}")
    print(f"  Challenge (hex): {hex(challenge)}")
    print(f"  Challenge (bits): {challenge.bit_length()}")
    
    # Demostrar determinismo
    challenge2 = hash_to_challenge(*elements)
    print(f"\nDeterminismo:")
    print(f"  Primer hash:  {challenge}")
    print(f"  Segundo hash: {challenge2}")
    print(f"  Iguales: {challenge == challenge2}")
    
    # Demostrar sensibilidad
    elements_modified = [12345, 67891, "context_string"]  # Cambio mínimo
    challenge3 = hash_to_challenge(*elements_modified)
    print(f"\nSensibilidad (elemento cambiado: 67890 -> 67891):")
    print(f"  Hash original: {challenge}")
    print(f"  Hash nuevo:    {challenge3}")
    print(f"  Diferentes: {challenge != challenge3}")


def main():
    """Ejecuta todos los ejemplos"""
    print("\n" + "█"*70)
    print("█" + " "*15 + "EJEMPLOS DE USO DE COMPONENTES" + " "*23 + "█")
    print("█"*70)
    
    ejemplos = [
        ejemplo_1_generar_primos,
        ejemplo_2_elgamal_basico,
        ejemplo_3_homomorfia,
        ejemplo_4_nizk,
        ejemplo_5_tokens,
        ejemplo_6_logaritmo_discreto,
        ejemplo_7_hash_fiat_shamir
    ]
    
    for ejemplo in ejemplos:
        try:
            ejemplo()
            print("\n✓ Ejemplo completado exitosamente")
        except Exception as e:
            print(f"\n✗ Error en ejemplo: {e}")
            import traceback
            traceback.print_exc()
        
        input("\nPresiona Enter para continuar al siguiente ejemplo...")
    
    print("\n" + "█"*70)
    print("█" + " "*20 + "TODOS LOS EJEMPLOS COMPLETADOS" + " "*17 + "█")
    print("█"*70)


if __name__ == "__main__":
    main()
