#!/usr/bin/env python3
"""
Sistema de Votación Electrónica con Criptografía ElGamal Multiplicativa
Demostración completa con pruebas NIZK y tokens de un solo uso

Este programa simula una elección con las siguientes características:
- Cifrado ElGamal multiplicativo para cada voto
- Acumulación homomórfica de votos cifrados
- Pruebas NIZK (Zero-Knowledge) que certifican la validez de cada voto
- Sistema de tokens para prevenir votación doble
- Solo se revela el conteo total, nunca los votos individuales
"""

import time
from voting_system import VotingAuthority, Voter, VotingCenter, TallyingCenter


def print_header():
    """Imprime el encabezado del sistema"""
    print("\n" + "█"*70)
    print("█" + " "*68 + "█")
    print("█" + " "*15 + "SISTEMA DE VOTACIÓN ELECTRÓNICA" + " "*22 + "█")
    print("█" + " "*10 + "Criptografía Homomórfica ElGamal + NIZK" + " "*19 + "█")
    print("█" + " "*68 + "█")
    print("█"*70)
    print("\n  Este sistema demuestra:")
    print("    ✓ Privacidad: Los votos individuales permanecen secretos")
    print("    ✓ Verificabilidad: Cada voto incluye una prueba NIZK")
    print("    ✓ Integridad: Solo se cuentan votos válidos")
    print("    ✓ Prevención de fraude: Tokens de un solo uso")
    print()


def simulate_election():
    """Simula una elección completa"""
    
    print_header()
    
    # =========================================================================
    # FASE 1: CONFIGURACIÓN DEL SISTEMA
    # =========================================================================
    
    print("\n" + "▓"*70)
    print("▓ FASE 1: CONFIGURACIÓN DEL SISTEMA")
    print("▓"*70)
    
    # Crear autoridad electoral
    authority = VotingAuthority(bits=512)
    
    # Generar parámetros y claves
    public_key = authority.setup_election()
    
    time.sleep(0.5)
    
    # =========================================================================
    # FASE 2: REGISTRO DE VOTANTES
    # =========================================================================
    
    print("\n" + "▓"*70)
    print("▓ FASE 2: REGISTRO DE VOTANTES")
    print("▓"*70)
    
    # Lista de votantes (simulación de aula)
    voter_ids = [
        "Alice_2024",
        "Bob_2024",
        "Carlos_2024",
        "Diana_2024",
        "Elena_2024",
        "Franco_2024",
        "Gloria_2024",
        "Héctor_2024"
    ]
    
    # Registrar votantes y emitir tokens
    tokens = authority.register_voters(voter_ids)
    
    time.sleep(0.5)
    
    # =========================================================================
    # FASE 3: EMISIÓN DE VOTOS
    # =========================================================================
    
    print("\n" + "▓"*70)
    print("▓ FASE 3: EMISIÓN DE VOTOS")
    print("▓"*70)
    
    print("\nPregunta: ¿Está de acuerdo con extender el horario de clases?")
    print()
    
    # Crear centro de votación
    voting_center = VotingCenter(authority.token_system, public_key, authority.auditoria)
    
    # Simular votos de cada participante
    # Cada votante elige SÍ (True) o NO (False)
    votes_to_cast = [
        ("Alice_2024", True),    # SÍ
        ("Bob_2024", False),     # NO
        ("Carlos_2024", True),   # SÍ
        ("Diana_2024", True),    # SÍ
        ("Elena_2024", False),   # NO
        ("Franco_2024", True),   # SÍ
        ("Gloria_2024", False),  # NO
        ("Héctor_2024", True),   # SÍ
    ]
    
    for voter_id, vote_choice in votes_to_cast:
        print(f"\n{'='*70}")
        print(f"Votante: {voter_id}")
        print(f"{'='*70}")
        
        # Crear objeto votante
        voter = Voter(voter_id, tokens[voter_id])
        
        # Cifrar voto y generar prueba NIZK
        print(f"  → Cifrando voto (privado: {'SÍ' if vote_choice else 'NO'})...")
        encrypted_vote = voter.cast_vote(vote_choice, public_key)
        
        print(f"    Voto cifrado generado:")
        print(f"      v = {encrypted_vote.ciphertext.v % 10000}... (truncado)")
        print(f"      e = {encrypted_vote.ciphertext.e % 10000}... (truncado)")
        print(f"    ✓ Prueba NIZK generada")
        
        # Enviar voto al centro de votación
        print(f"\n  → Enviando voto al centro de votación...")
        voting_center.receive_vote(encrypted_vote)
        
        time.sleep(0.3)
    
    # =========================================================================
    # FASE 4: DEMOSTRACIÓN DE SEGURIDAD
    # =========================================================================
    
    print("\n" + "▓"*70)
    print("▓ FASE 4: DEMOSTRACIÓN DE SEGURIDAD")
    print("▓"*70)
    
    print("\n→ Intentando voto doble (debe ser rechazado)...")
    
    # Intentar que Alice vote de nuevo
    alice_voter = Voter("Alice_2024", tokens["Alice_2024"])
    duplicate_vote = alice_voter.cast_vote(False, public_key)
    
    print(f"\n{'='*70}")
    print(f"Votante: Alice_2024 (INTENTO DE VOTO DOBLE)")
    print(f"{'='*70}")
    
    success = voting_center.receive_vote(duplicate_vote)
    
    if not success:
        print("\n  ✓ Sistema de seguridad funcionando correctamente")
        print("    El voto doble fue detectado y rechazado")
    
    time.sleep(0.5)
    
    # =========================================================================
    # FASE 5: RECUENTO HOMOMÓRFICO
    # =========================================================================
    
    print("\n" + "▓"*70)
    print("▓ FASE 5: RECUENTO Y PUBLICACIÓN DE RESULTADOS")
    print("▓"*70)
    
    # Crear centro de recuento
    tallying_center = TallyingCenter(authority.elgamal, authority.auditoria, public_key)
    
    # Obtener votos válidos
    valid_votes = voting_center.get_valid_votes()
    
    # Realizar recuento homomórfico (con mixnet)
    yes_count, no_count = tallying_center.tally_votes(valid_votes)
    
    # Publicar resultados
    stats = voting_center.get_statistics()
    tallying_center.publish_results(yes_count, no_count, stats)
    
    # =========================================================================
    # FASE 6: AUDITORÍA
    # =========================================================================
    
    print("\n" + "▓"*70)
    print("▓ FASE 6: VERIFICACIÓN DE AUDITORÍA")
    print("▓"*70)
    
    # Verificar integridad de la cadena de auditoría
    authority.auditoria.verificar_integridad()
    
    # Mostrar resumen
    authority.auditoria.imprimir_resumen()


def main():
    """Función principal"""
    try:
        simulate_election()
    except KeyboardInterrupt:
        print("\n\nSimulación interrumpida por el usuario.")
    except Exception as e:
        print(f"\n\nError durante la simulación: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
