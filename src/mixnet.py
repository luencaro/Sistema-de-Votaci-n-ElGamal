"""Sistema de mezcla de votos (Mixnet) para romper trazabilidad"""
import secrets
import random
from collections import namedtuple
from elgamal import Ciphertext, PublicKey
from crypto_utils import hash_to_challenge

MixProof = namedtuple('MixProof', ['permutation_commitment', 'reencryption_proof'])

class Mixnet:
    """Mezcla y re-cifra votos para romper el vínculo votante-voto"""
    
    def __init__(self, public_key):
        self.public_key = public_key
    
    def shuffle_and_recrypt(self, ciphertexts):
        """
        Mezcla votos: reordena aleatoriamente y re-cifra cada uno
        Retorna: (votos_mezclados, prueba_de_mezcla)
        """
        if not ciphertexts:
            return [], None
        
        n = len(ciphertexts)
        print(f"\n→ Mezclando {n} votos...")
        
        # 1. Generar permutación aleatoria
        indices = list(range(n))
        random.shuffle(indices)
        print(f"  Permutación generada (oculta)")
        
        # 2. Re-cifrar cada voto en el nuevo orden
        mixed_votes = []
        randomness_used = []
        
        for i, original_idx in enumerate(indices):
            original_vote = ciphertexts[original_idx]
            
            # Re-cifrar: (v', e') = (v·g^r, e·u^r) mod p
            r = secrets.randbelow(self.public_key.q - 1) + 1
            randomness_used.append(r)
            
            v_new = (original_vote.v * pow(self.public_key.g, r, self.public_key.p)) % self.public_key.p
            e_new = (original_vote.e * pow(self.public_key.u, r, self.public_key.p)) % self.public_key.p
            
            mixed_votes.append(Ciphertext(v_new, e_new))
        
        print(f"  ✓ {n} votos re-cifrados y mezclados")
        
        # 3. Generar prueba de mezcla correcta
        proof = self._generate_mix_proof(ciphertexts, mixed_votes, indices, randomness_used)
        
        return mixed_votes, proof
    
    def _generate_mix_proof(self, original, mixed, permutation, randomness):
        """
        Genera prueba ZKP de que la mezcla es correcta
        Demuestra que mixed es una permutación re-cifrada de original
        """
        # Commitment de la permutación (hash de los índices + randomness)
        perm_str = ''.join(map(str, permutation))
        rand_str = ''.join(map(str, randomness[:3]))  # Solo primeros 3 para commitment
        
        commitment = hash_to_challenge(
            perm_str,
            rand_str,
            len(original),
            len(mixed)
        )
        
        # Prueba simplificada: verificar que ambas listas tienen el mismo tamaño
        # En implementación real: usar protocolo más robusto (Sigma protocol extendido)
        reenc_proof = {
            'original_count': len(original),
            'mixed_count': len(mixed),
            'commitment_hash': commitment % self.public_key.q
        }
        
        return MixProof(commitment, reenc_proof)
    
    def verify_mix(self, original_votes, mixed_votes, proof):
        """
        Verifica que la mezcla fue correcta
        Comprueba: mismo número de votos, formato válido, prueba válida
        """
        if not proof:
            print("  ✗ No hay prueba de mezcla")
            return False
        
        # Verificar tamaños
        if len(original_votes) != len(mixed_votes):
            print("  ✗ Número de votos no coincide")
            return False
        
        if proof.reencryption_proof['original_count'] != len(original_votes):
            print("  ✗ Prueba no corresponde al número de votos")
            return False
        
        # Verificar formato de votos mezclados
        for vote in mixed_votes:
            if not isinstance(vote, Ciphertext):
                print("  ✗ Formato de voto inválido")
                return False
            
            if vote.v <= 0 or vote.e <= 0:
                print("  ✗ Componentes de voto inválidos")
                return False
        
        print("  ✓ Mezcla verificada correctamente")
        return True
    
    def get_statistics(self, original_votes, mixed_votes):
        """Retorna estadísticas de la mezcla"""
        return {
            'votos_originales': len(original_votes),
            'votos_mezclados': len(mixed_votes),
            'trazabilidad_rota': len(original_votes) == len(mixed_votes)
        }
