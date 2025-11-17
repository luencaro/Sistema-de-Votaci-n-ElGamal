"""Sistema de auditoría con registro tipo blockchain para trazabilidad"""
import time
import json
from collections import namedtuple
from crypto_utils import hash_to_challenge

RegistroEvento = namedtuple('RegistroEvento', ['timestamp', 'tipo', 'datos', 'hash_previo', 'hash_actual'])

class SistemaAuditoria:
    """Registro inmutable de eventos electorales con cadena de hashes"""
    
    def __init__(self):
        self.eventos = []
        self.hash_genesis = self._calcular_hash("GENESIS_BLOCK", 0, {})
        print("  ✓ Sistema de auditoría inicializado")
        print(f"    Hash génesis: {self.hash_genesis}")
    
    def registrar_evento(self, tipo, datos):
        """
        Registra un evento en la cadena de auditoría
        Tipo: 'SETUP', 'REGISTRO', 'VOTO', 'MEZCLA', 'CONTEO'
        """
        timestamp = int(time.time() * 1000)  # milisegundos
        
        # Obtener hash del evento previo
        if self.eventos:
            hash_previo = self.eventos[-1].hash_actual
        else:
            hash_previo = self.hash_genesis
        
        # Calcular hash del evento actual
        hash_actual = self._calcular_hash(tipo, timestamp, datos, hash_previo)
        
        # Crear y guardar evento
        evento = RegistroEvento(
            timestamp=timestamp,
            tipo=tipo,
            datos=datos,
            hash_previo=hash_previo,
            hash_actual=hash_actual
        )
        
        self.eventos.append(evento)
        
        # Log simplificado
        hash_corto = str(hash_actual)[:8]
        print(f"  📋 Evento registrado: {tipo} (hash: {hash_corto}...)")
        
        return hash_actual
    
    def _calcular_hash(self, tipo, timestamp, datos, hash_previo=None):
        """Calcula hash criptográfico del evento"""
        # Serializar datos de forma determinista
        datos_str = json.dumps(datos, sort_keys=True) if isinstance(datos, dict) else str(datos)
        
        # Combinar todos los componentes
        componentes = [
            tipo,
            str(timestamp),
            datos_str,
            str(hash_previo) if hash_previo else ""
        ]
        
        # Usar nuestra función hash existente
        return hash_to_challenge(*componentes)
    
    def verificar_integridad(self):
        """
        Verifica la integridad de toda la cadena de auditoría
        Retorna True si la cadena es válida, False si fue alterada
        """
        print("\n" + "="*70)
        print("VERIFICACIÓN DE INTEGRIDAD DE AUDITORÍA")
        print("="*70)
        
        if not self.eventos:
            print("  ℹ No hay eventos para verificar")
            return True
        
        # Verificar cada evento
        for i, evento in enumerate(self.eventos):
            # Verificar hash previo
            if i == 0:
                expected_prev = self.hash_genesis
            else:
                expected_prev = self.eventos[i-1].hash_actual
            
            if evento.hash_previo != expected_prev:
                print(f"  ✗ Evento {i}: hash previo inválido")
                return False
            
            # Recalcular hash actual
            hash_recalculado = self._calcular_hash(
                evento.tipo,
                evento.timestamp,
                evento.datos,
                evento.hash_previo
            )
            
            if hash_recalculado != evento.hash_actual:
                print(f"  ✗ Evento {i}: hash actual no coincide (posible alteración)")
                return False
        
        print(f"  ✓ {len(self.eventos)} eventos verificados correctamente")
        print("  ✓ Cadena de auditoría íntegra")
        print("="*70)
        return True
    
    def exportar_registro(self):
        """Exporta el registro completo de auditoría"""
        registro = {
            'hash_genesis': self.hash_genesis,
            'total_eventos': len(self.eventos),
            'eventos': []
        }
        
        for evento in self.eventos:
            registro['eventos'].append({
                'timestamp': evento.timestamp,
                'tipo': evento.tipo,
                'datos': evento.datos,
                'hash_previo': evento.hash_previo,
                'hash_actual': evento.hash_actual
            })
        
        return registro
    
    def imprimir_resumen(self):
        """Imprime resumen del registro de auditoría"""
        print("\n" + "="*70)
        print("RESUMEN DE AUDITORÍA")
        print("="*70)
        print(f"Total de eventos registrados: {len(self.eventos)}")
        
        # Contar por tipo
        tipos = {}
        for evento in self.eventos:
            tipos[evento.tipo] = tipos.get(evento.tipo, 0) + 1
        
        print("\nEventos por tipo:")
        for tipo, count in sorted(tipos.items()):
            print(f"  {tipo}: {count}")
        
        if self.eventos:
            print(f"\nPrimer evento: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.eventos[0].timestamp/1000))}")
            print(f"Último evento: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.eventos[-1].timestamp/1000))}")
        
        print("="*70)
    
    def obtener_eventos_por_tipo(self, tipo):
        """Retorna todos los eventos de un tipo específico"""
        return [e for e in self.eventos if e.tipo == tipo]
    
    def obtener_estadisticas(self):
        """Retorna estadísticas del sistema de auditoría"""
        tipos = {}
        for evento in self.eventos:
            tipos[evento.tipo] = tipos.get(evento.tipo, 0) + 1
        
        return {
            'total_eventos': len(self.eventos),
            'eventos_por_tipo': tipos,
            'hash_genesis': self.hash_genesis,
            'integridad_verificada': self.verificar_integridad() if self.eventos else True
        }
