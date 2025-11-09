"""Sistema de tokens para prevenir votación doble"""
import secrets
import hashlib
from collections import namedtuple
from datetime import datetime

VoterToken = namedtuple('VoterToken', ['voter_id', 'token', 'issued_at'])


class TokenSystem:
    """Sistema de gestión de tokens de votante"""
    
    def __init__(self, secret_key=None):
        self.secret_key = secret_key or secrets.token_bytes(32)
        self.issued_tokens = {}
        self.used_tokens = set()
        self.voter_has_voted = set()
    
    def issue_token(self, voter_id):
        """Emite token único para votante usando HMAC-SHA256"""
        if voter_id in self.issued_tokens:
            raise ValueError(f"El votante {voter_id} ya tiene un token emitido")
        
        timestamp = datetime.now().isoformat()
        nonce = secrets.token_hex(16)
        message = f"{voter_id}||{timestamp}||{nonce}".encode('utf-8')
        hmac = hashlib.sha256(self.secret_key + message).hexdigest()
        token = f"{voter_id}:{hmac}"
        
        voter_token = VoterToken(voter_id, token, timestamp)
        self.issued_tokens[voter_id] = voter_token
        return voter_token
    
    def verify_token(self, token):
        """Verifica si token es válido y no ha sido usado"""
        try:
            voter_id = token.split(':')[0]
        except:
            return False, "Token malformado"
        
        if voter_id not in self.issued_tokens:
            return False, f"Token no emitido para votante {voter_id}"
        
        if self.issued_tokens[voter_id].token != token:
            return False, "Token no coincide con el emitido"
        
        if token in self.used_tokens:
            return False, "Token ya utilizado (voto doble detectado)"
        
        if voter_id in self.voter_has_voted:
            return False, f"Votante {voter_id} ya emitió su voto"
        
        return True, "Token válido"
    
    def mark_token_used(self, token):
        """Marca token como usado después de votar"""
        voter_id = token.split(':')[0]
        self.used_tokens.add(token)
        self.voter_has_voted.add(voter_id)
    
    def get_voter_count(self):
        """Retorna número total de votantes registrados"""
        return len(self.issued_tokens)
    
    def get_voted_count(self):
        """Retorna número de votantes que ya votaron"""
        return len(self.voter_has_voted)
    
    def get_remaining_voters(self) -> int:
        """Retorna el número de votantes que aún no han votado"""
        return self.get_voter_count() - self.get_voted_count()
