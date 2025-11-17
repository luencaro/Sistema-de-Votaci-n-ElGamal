"""Sistema de votación electrónica con ElGamal"""
import secrets
from collections import namedtuple
from elgamal import ElGamalSystem, PublicKey, Ciphertext
from nizk import NIZKSystem, NIZKProof
from token_system import TokenSystem, VoterToken
from mixnet import Mixnet
from auditoria import SistemaAuditoria

EncryptedVote = namedtuple('EncryptedVote', ['voter_id', 'token', 'ciphertext', 'proof'])


class VotingAuthority:
    """
    Autoridad Electoral - Genera parámetros del sistema y emite tokens
    """
    
    def __init__(self, bits= 512):
        """
        Inicializa la autoridad electoral
        
        Args:
            bits: Tamaño en bits del primo p para ElGamal
        """
        self.elgamal = ElGamalSystem(bits)
        self.token_system = TokenSystem()
        self.auditoria = SistemaAuditoria()
        self.public_key= None
        self.registered_voters= []
    
    def setup_election(self):
        """
        Configura el sistema electoral generando parámetros y claves
        
        Returns:
            Clave pública del sistema
        """
        print("\n" + "█"*70)
        print("█" + " "*25 + "CONFIGURACIÓN" + " "*30 + "█")
        print("█" + " "*21 + "AUTORIDAD ELECTORAL" + " "*26 + "█")
        print("█"*70)
        
        # Generar claves ElGamal
        self.public_key, _ = self.elgamal.generate_keys()
        
        # Registrar en auditoría
        self.auditoria.registrar_evento('SETUP', {
            'p': str(self.public_key.p)[:20] + '...',
            'g': str(self.public_key.g)[:20] + '...',
            'bits': self.elgamal.bits
        })
        
        return self.public_key
    
    def register_voters(self, voter_ids):
        """
        Registra votantes y emite tokens de elegibilidad
        
        Args:
            voter_ids: Lista de identificadores de votantes
        
        Returns:
            Diccionario voter_id -> token
        """
        print("\n" + "="*70)
        print("REGISTRO DE VOTANTES Y EMISIÓN DE TOKENS")
        print("="*70)
        
        tokens = {}
        
        for voter_id in voter_ids:
            token = self.token_system.issue_token(voter_id)
            tokens[voter_id] = token
            self.registered_voters.append(voter_id)
            print(f"  ✓ Votante registrado: {voter_id}")
            print(f"    Token: {token.token[:50]}...")
            
            # Registrar en auditoría
            self.auditoria.registrar_evento('REGISTRO', {
                'voter_id': voter_id,
                'token_emitido': True
            })
        
        print(f"\nTotal de votantes registrados: {len(voter_ids)}")
        print("="*70)
        
        return tokens


class Voter:
    """
    Votante - Cifra su voto y genera prueba NIZK
    """
    
    def __init__(self, voter_id, token):
        """
        Inicializa un votante
        
        Args:
            voter_id: Identificador del votante
            token: Token de elegibilidad
        """
        self.voter_id = voter_id
        self.token = token
    
    def cast_vote(self, vote, public_key):
        """
        Emite un voto cifrado con prueba NIZK
        
        Args:
            vote, False para NO
            public_key: Clave pública del sistema
        
        Returns:
            Voto cifrado con prueba
        """
        # Convertir booleano a bit
        vote_bit = 1 if vote else 0
        
        # Cifrar el voto
        elgamal_temp = ElGamalSystem()
        elgamal_temp.public_key = public_key
        ciphertext, randomness = elgamal_temp.encrypt(vote_bit, public_key)
        
        # Generar prueba NIZK de validez
        proof = NIZKSystem.generate_proof(vote_bit, ciphertext, randomness, public_key)
        
        return EncryptedVote(self.voter_id, self.token.token, ciphertext, proof)


class VotingCenter:
    """
    Centro de Votación - Valida y registra votos
    """
    
    def __init__(self, token_system, public_key, auditoria):
        """
        Inicializa el centro de votación
        
        Args:
            token_system: Sistema de tokens para validación
            public_key: Clave pública del sistema
            auditoria: Sistema de auditoría
        """
        self.token_system = token_system
        self.public_key = public_key
        self.auditoria = auditoria
        self.valid_votes= []
        self.rejected_votes= []  # (voter_id, razón)
    
    def receive_vote(self, encrypted_vote):
        """
        Recibe y valida un voto cifrado
        
        Args:
            encrypted_vote: Voto cifrado con prueba y token
        
        Returns:
            True si el voto fue aceptado
        """
        voter_id = encrypted_vote.voter_id
        
        print(f"\n  → Procesando voto de {voter_id}...")
        
        # 1. Validar token
        is_valid, message = self.token_system.verify_token(encrypted_vote.token)
        if not is_valid:
            print(f"    ✗ Token inválido: {message}")
            self.rejected_votes.append((voter_id, f"Token inválido: {message}"))
            return False
        
        print(f"    ✓ Token válido")
        
        # 2. Verificar prueba NIZK
        proof_valid = NIZKSystem.verify_proof(
            encrypted_vote.ciphertext,
            encrypted_vote.proof,
            self.public_key
        )
        
        if not proof_valid:
            print(f"    ✗ Prueba NIZK inválida")
            self.rejected_votes.append((voter_id, "Prueba NIZK inválida"))
            return False
        
        print(f"    ✓ Prueba NIZK verificada")
        
        # 3. Registrar voto y marcar token como usado
        self.valid_votes.append(encrypted_vote)
        self.token_system.mark_token_used(encrypted_vote.token)
        
        # 4. Registrar en auditoría
        self.auditoria.registrar_evento('VOTO', {
            'voter_id': voter_id,
            'voto_valido': True,
            'nizk_verificado': True
        })
        
        print(f"    ✓ Voto registrado exitosamente")
        
        return True
    
    def get_valid_votes(self):
        """
        Retorna solo los cifrados de los votos válidos
        
        Returns:
            Lista de cifrados válidos
        """
        return [vote.ciphertext for vote in self.valid_votes]
    
    def get_statistics(self):
        """Retorna estadísticas del proceso de votación"""
        return {
            'total_votes': len(self.valid_votes) + len(self.rejected_votes),
            'valid_votes': len(self.valid_votes),
            'rejected_votes': len(self.rejected_votes),
            'registered_voters': self.token_system.get_voter_count(),
            'participation_rate': len(self.valid_votes) / self.token_system.get_voter_count() * 100
        }


class TallyingCenter:
    """
    Centro de Recuento - Acumula votos y publica resultados
    """
    
    def __init__(self, elgamal, auditoria, public_key):
        """
        Inicializa el centro de recuento
        
        Args:
            elgamal: Sistema ElGamal con acceso a la clave privada
            auditoria: Sistema de auditoría
            public_key: Clave pública para mixnet
        """
        self.elgamal = elgamal
        self.auditoria = auditoria
        self.mixnet = Mixnet(public_key)
    
    def tally_votes(self, encrypted_votes):
        """
        Recuenta los votos usando acumulación homomórfica
        
        Args:
            encrypted_votes: Lista de votos cifrados
        
        Returns:
            Tupla (votos_a_favor, votos_en_contra)
        """
        print("\n" + "="*70)
        print("RECUENTO DE VOTOS - ACUMULACIÓN HOMOMÓRFICA")
        print("="*70)
        
        if not encrypted_votes:
            print("No hay votos para contar")
            return 0, 0
        
        print(f"\nTotal de votos cifrados recibidos: {len(encrypted_votes)}")
        
        # Mostrar algunos votos cifrados (incomprensibles sin la clave)
        print("\nEjemplos de votos cifrados (imposible determinar el voto individual):")
        for i, ct in enumerate(encrypted_votes[:3], 1):
            print(f"  Voto {i}: (v={ct.v % 10000}..., e={ct.e % 10000}...)")
        
        # PASO 1: Mezclar votos con Mixnet
        print("\n" + "="*70)
        print("FASE DE MEZCLA (MIXNET) - Romper trazabilidad")
        print("="*70)
        
        mixed_votes, mix_proof = self.mixnet.shuffle_and_recrypt(encrypted_votes)
        
        # Verificar mezcla
        if not self.mixnet.verify_mix(encrypted_votes, mixed_votes, mix_proof):
            print("  ✗ Error: Mezcla inválida")
            return 0, 0
        
        # Registrar mezcla en auditoría
        self.auditoria.registrar_evento('MEZCLA', {
            'votos_originales': len(encrypted_votes),
            'votos_mezclados': len(mixed_votes),
            'mezcla_verificada': True
        })
        
        print("="*70)
        
        # PASO 2: Acumular votos mezclados homomórficamente
        print("\n→ Multiplicando todos los cifrados homomórficamente...")
        aggregated = self.elgamal.homomorphic_add(mixed_votes)
        
        print(f"  Cifrado agregado calculado:")
        print(f"  v* = {aggregated.v % 10000}...")
        print(f"  e* = {aggregated.e % 10000}...")
        
        # Descifrar el agregado
        print("\n→ Descifrando el voto agregado...")
        total_yes = self.elgamal.decrypt_sum(aggregated, len(mixed_votes))
        
        total_no = len(mixed_votes) - total_yes
        
        # Registrar conteo en auditoría
        self.auditoria.registrar_evento('CONTEO', {
            'total_votos': len(mixed_votes),
            'votos_favor': total_yes,
            'votos_contra': total_no
        })
        
        print(f"\n✓ Suma de votos desencriptada: {total_yes}")
        print("="*70)
        
        return total_yes, total_no
    
    def publish_results(self, yes_votes, no_votes, stats):
        """
        Publica los resultados finales de la votación
        
        Args:
            yes_votes: Número de votos a favor
            no_votes: Número de votos en contra
            stats: Estadísticas adicionales
        """
        print("\n" + "█"*70)
        print("█" + " "*23 + "RESULTADOS FINALES" + " "*27 + "█")
        print("█"*70)
        
        total = yes_votes + no_votes
        
        print(f"\n  Pregunta: ¿Está de acuerdo con la propuesta?")
        print(f"\n  {'Opción':<20} {'Votos':<10} {'Porcentaje':<15}")
        print("  " + "-"*45)
        
        yes_pct = (yes_votes / total * 100) if total > 0 else 0
        no_pct = (no_votes / total * 100) if total > 0 else 0
        
        print(f"  {'SÍ':<20} {yes_votes:<10} {yes_pct:>6.2f}%")
        print(f"  {'NO':<20} {no_votes:<10} {no_pct:>6.2f}%")
        print("  " + "-"*45)
        print(f"  {'TOTAL':<20} {total:<10} {'100.00%':>10}")
        
        print(f"\n  Estadísticas:")
        print(f"    • Votantes registrados: {stats['registered_voters']}")
        print(f"    • Votos emitidos: {stats['total_votes']}")
        print(f"    • Votos válidos: {stats['valid_votes']}")
        print(f"    • Votos rechazados: {stats['rejected_votes']}")
        print(f"    • Participación: {stats['participation_rate']:.2f}%")
        
        print("\n" + "█"*70)
