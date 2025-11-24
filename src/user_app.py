#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Aplicación Interactiva del Sistema de Votación ElGamal
Interfaz fácil de usar para usuarios finales
"""

import os
import sys
import time
from datetime import datetime
from voting_system import VotingAuthority, Voter, VotingCenter, TallyingCenter

if sys.platform == "win32":
    import codecs
    sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())
    sys.stderr = codecs.getwriter("utf-8")(sys.stderr.detach())


def limpiar_pantalla():
    os.system('cls' if os.name == 'nt' else 'clear')


def mostrar_titulo():
    print("\n" + "="*70)
    print("=" + " "*15 + "  SISTEMA DE VOTACION SEGURA  " + " "*22 + "=")
    print("=" + " "*10 + "Votacion Electronica con Criptografia ElGamal" + " "*13 + "=")
    print("="*70 + "\n")


def mostrar_menu_principal():
    print("\n" + "="*70)
    print("                          MENU PRINCIPAL")
    print("="*70)
    print("\n  1. Modo Administrador (Configurar y Gestionar Eleccion)")
    print("  2. Modo Votante (Emitir Voto)")
    print("  3. Ver Resultados de Eleccion")
    print("  4. Acerca del Sistema")
    print("  5. Salir")
    print("\n" + "="*70)


def mostrar_menu_admin():
    print("\n" + "="*70)
    print("                     MENU ADMINISTRADOR")
    print("="*70)
    print("\n  1. Crear Nueva Eleccion")
    print("  2. Registrar Votantes")
    print("  3. Cerrar Eleccion y Contar Votos")
    print("  4. Ver Estado de la Eleccion")
    print("  5. Volver al Menu Principal")
    print("\n" + "="*70)


def pausar():
    input("\n>> Presiona Enter para continuar...")


def obtener_opcion(mensaje, opciones_validas):
    """
    Obtiene una opción válida del usuario
    
    Args:
        mensaje: Mensaje a mostrar
        opciones_validas: Lista de opciones válidas
    
    Returns:
        Opción seleccionada
    """
    while True:
        opcion = input(f"\n{mensaje}: ").strip()
        if opcion in opciones_validas:
            return opcion
        print(f"[X] Opcion invalida. Por favor, elige entre: {', '.join(opciones_validas)}")


class AplicacionVotacion:
    """Clase principal de la aplicación de votación"""
    
    def __init__(self):
        self.authority = None
        self.voting_center = None
        self.tallying_center = None
        self.public_key = None
        self.tokens = {}
        self.pregunta_votacion = ""
        self.eleccion_activa = False
        self.eleccion_cerrada = False
        self.resultados = None
        self.estadisticas = None
    
    def ejecutar(self):
        while True:
            limpiar_pantalla()
            mostrar_titulo()
            mostrar_menu_principal()
            
            opcion = obtener_opcion("Selecciona una opción [1-5]", ["1", "2", "3", "4", "5"])
            
            if opcion == "1":
                self.modo_administrador()
            elif opcion == "2":
                self.modo_votante()
            elif opcion == "3":
                self.ver_resultados()
            elif opcion == "4":
                self.acerca_del_sistema()
            elif opcion == "5":
                self.salir()
                break
    
    def modo_administrador(self):
        while True:
            limpiar_pantalla()
            mostrar_titulo()
            mostrar_menu_admin()
            
            opcion = obtener_opcion("Selecciona una opción [1-5]", ["1", "2", "3", "4", "5"])
            
            if opcion == "1":
                self.crear_eleccion()
            elif opcion == "2":
                self.registrar_votantes()
            elif opcion == "3":
                self.cerrar_y_contar()
            elif opcion == "4":
                self.ver_estado_eleccion()
            elif opcion == "5":
                break
    
    def crear_eleccion(self):
        limpiar_pantalla()
        mostrar_titulo()
        print("═"*70)
        print("                      CREAR NUEVA ELECCIÓN")
        print("═"*70)
        
        if self.eleccion_activa:
            print("Ya existe una elección activa.")
            respuesta = obtener_opcion("¿Deseas crear una nueva elección? (Esto eliminará la actual) [S/N]", ["S", "s", "N", "n"])
            if respuesta.upper() == "N":
                pausar()
                return
        
        print("Configura tu elección:")
        while True:
            pregunta = input("Ingresa la pregunta para la votación: ").strip()
            if pregunta:
                self.pregunta_votacion = pregunta
                break
            print("La pregunta no puede estar vacía.")
        
        print("Configurando parámetros de seguridad...")
        print("   (Esto puede tomar unos segundos)")
        
        try:
            self.authority = VotingAuthority(bits=512)
            
            self.public_key = self.authority.setup_election()
            
            self.tokens = {}
            self.eleccion_activa = True
            self.eleccion_cerrada = False
            self.resultados = None
            self.estadisticas = None
            self.voting_center = None
            self.tallying_center = None
            
            print("¡Elección creada exitosamente!")
            print(f"Pregunta: {self.pregunta_votacion}")
            print("   Opciones: SÍ / NO")
            
        except Exception as e:
            print(f"Error al crear la elección: {e}")
        
        pausar()
    
    def registrar_votantes(self):
        limpiar_pantalla()
        mostrar_titulo()
        print("═"*70)
        print("                      REGISTRAR VOTANTES")
        print("═"*70)
        
        if not self.eleccion_activa:
            print("No hay una elección activa. Por favor, crea una elección primero.")
            pausar()
            return
        
        if self.voting_center is not None:
            print("Los votantes ya fueron registrados y la votación está en curso.")
            respuesta = obtener_opcion("¿Deseas volver a registrar votantes? (Reiniciará la votación) [S/N]", ["S", "s", "N", "n"])
            if respuesta.upper() == "N":
                pausar()
                return
        
        print(f"\nElección activa: {self.pregunta_votacion}")
        print("\nIngresa los IDs de los votantes (uno por línea)")
        print("   Ingresa una línea vacía cuando termines")
        print("\n   Ejemplo: votante_001, Juan_Perez, etc.\n")
        
        voter_ids = []
        contador = 1
        
        while True:
            voter_id = input(f"  Votante #{contador}: ").strip()
            
            if not voter_id:
                if len(voter_ids) == 0:
                    print("Debes registrar al menos un votante.")
                    continue
                break
            
            if voter_id in voter_ids:
                print(f"  El votante '{voter_id}' ya fue registrado.")
                continue
            
            voter_ids.append(voter_id)
            contador += 1
        
        # Registrar votantes
        print(f"\nRegistrando {len(voter_ids)} votantes...")
        
        try:
            self.tokens = self.authority.register_voters(voter_ids)
            
            # Crear centro de votación
            self.voting_center = VotingCenter(
                self.authority.token_system,
                self.public_key,
                self.authority.auditoria
            )
            
            print(f"\n✅ ¡{len(voter_ids)} votantes registrados exitosamente!")
            print("\n📧 Tokens de votación emitidos:")
            print("   (En un sistema real, estos se enviarían de forma segura a cada votante)\n")
            
            for voter_id in voter_ids[:5]:  # Mostrar solo los primeros 5
                token_preview = self.tokens[voter_id].token[:40]
                print(f"   • {voter_id}: {token_preview}...")
            
            if len(voter_ids) > 5:
                print(f"   ... y {len(voter_ids) - 5} más")
            
            print("IMPORTANTE: Guarda estos tokens de forma segura.")
            print("   Los votantes necesitarán su token para votar.")
            
    
            respuesta = obtener_opcion("\n¿Deseas guardar los tokens en un archivo? [S/N]", ["S", "s", "N", "n"])
            if respuesta.upper() == "S":
                self.guardar_tokens()
            
        except Exception as e:
            print(f" Error al registrar votantes: {e}")
        
        pausar()
    
    def guardar_tokens(self):
        """Guarda los tokens en un archivo"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        nombre_archivo = f"tokens_votacion_{timestamp}.txt"
        
        try:
            with open(nombre_archivo, 'w', encoding='utf-8') as f:
                f.write("="*70 + "\n")
                f.write("           TOKENS DE VOTACIÓN - CONFIDENCIAL\n")
                f.write("="*70 + "\n\n")
                f.write(f"Elección: {self.pregunta_votacion}\n")
                f.write(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total votantes: {len(self.tokens)}\n\n")
                f.write("="*70 + "\n\n")
                
                for voter_id, token in self.tokens.items():
                    f.write(f"Votante: {voter_id}\n")
                    f.write(f"Token: {token.token}\n\n")
            
            ruta_completa = os.path.abspath(nombre_archivo)
            print(f"Tokens guardados en: {ruta_completa}")
            
        except Exception as e:
            print(f"Error al guardar tokens: {e}")
    
    def modo_votante(self):
        """Modo para que los votantes emitan su voto"""
        limpiar_pantalla()
        mostrar_titulo()
        print("═"*70)
        print("                       EMITIR VOTO")
        print("═"*70)
        
        if not self.eleccion_activa:
            print("No hay una elección activa en este momento.")
            pausar()
            return
        
        if self.voting_center is None:
            print("[X] Los votantes aun no han sido registrados.")
            print("   Por favor, contacta al administrador.")
            pausar()
            return
        
        if self.eleccion_cerrada:
            print("La elección ya ha sido cerrada.")
            print("   No se pueden emitir más votos.")
            pausar()
            return
        
        print(f"Pregunta: {self.pregunta_votacion}")
        print("   Opciones: SÍ / NO")
        
        # Solicitar ID de votante
        print("Identificación del votante:")
        voter_id = input("   Ingresa tu ID de votante: ").strip()
        
        if not voter_id:
            print("ID de votante no puede estar vacío.")
            pausar()
            return
        
        # Verificar que el votante esté registrado
        if voter_id not in self.tokens:
            print(f"El votante '{voter_id}' no está registrado.")
            print("   Por favor, contacta al administrador.")
            pausar()
            return
        
        # Solicitar token
        print("Autenticación:")
        token_input = input("   Ingresa tu token de votación: ").strip()
        
        if not token_input:
            print("Token no puede estar vacío.")
            pausar()
            return
        
        # Verificar que el token coincida
        if token_input != self.tokens[voter_id].token:
            print("Token inválido.")
            print("   El token no coincide con tu ID de votante.")
            pausar()
            return
        
        # Solicitar voto
        print("Emitir voto:")
        print("   1. SÍ")
        print("   2. NO")
        
        voto_opcion = obtener_opcion("   Selecciona tu voto [1/2]", ["1", "2"])
        vote_choice = True if voto_opcion == "1" else False
        voto_texto = "SÍ" if vote_choice else "NO"
        
        # Confirmar voto
        print("Confirmación:")
        print(f"   Has seleccionado: {voto_texto}")
        confirmacion = obtener_opcion("   ¿Confirmas tu voto? [S/N]", ["S", "s", "N", "n"])
        
        if confirmacion.upper() == "N":
            print("Voto cancelado.")
            pausar()
            return
        
        # Procesar voto
        print("Procesando tu voto...")
        print("   • Cifrando voto...")
        
        try:
            # Crear objeto votante
            voter = Voter(voter_id, self.tokens[voter_id])
            
            # Cifrar voto y generar prueba NIZK
            encrypted_vote = voter.cast_vote(vote_choice, self.public_key)
            print("   • Generando prueba criptográfica...")
            
            # Enviar voto al centro de votación
            print("   • Enviando voto al centro de votación...")
            success = self.voting_center.receive_vote(encrypted_vote)
            
            if success:
                print("¡Voto registrado exitosamente!")
                print("Tu voto ha sido cifrado y solo se revelará el conteo total.")
                print("   Tu privacidad está garantizada.")
            else:
                print("Tu voto no pudo ser registrado.")
                print("   Posibles razones:")
                print("   • Ya votaste anteriormente")
                print("   • Token inválido o ya usado")
                print("   • Error en la prueba criptográfica")
        
        except Exception as e:
            print(f"Error al procesar el voto: {e}")
        
        pausar()
    
    def cerrar_y_contar(self):
        """Cierra la elección y cuenta los votos"""
        limpiar_pantalla()
        mostrar_titulo()
        print("═"*70)
        print("                   CERRAR ELECCIÓN Y CONTAR VOTOS")
        print("═"*70)
        
        if not self.eleccion_activa:
            print("No hay una elección activa.")
            pausar()
            return
        
        if self.voting_center is None:
            print("No se han registrado votantes.")
            pausar()
            return
        
        if self.eleccion_cerrada:
            print("La elección ya fue cerrada previamente.")
            print("   Puedes ver los resultados en el menú principal.")
            pausar()
            return
        
        stats = self.voting_center.get_statistics()
        
        print(f"Estado actual:")
        print(f"   • Votantes registrados: {stats['registered_voters']}")
        print(f"   • Votos recibidos: {stats['valid_votes']}")
        print(f"   • Participación: {stats['participation_rate']:.1f}%")
        
        print("ADVERTENCIA:")
        print("   Una vez cerrada la elección, no se podrán emitir más votos.")
        
        confirmacion = obtener_opcion("\n¿Deseas cerrar la elección y proceder al conteo? [S/N]", ["S", "s", "N", "n"])
        
        if confirmacion.upper() == "N":
            print("Operación cancelada.")
            pausar()
            return
        
        print("Procesando votación...")
        
        try:
            # Crear centro de recuento
            self.tallying_center = TallyingCenter(
                self.authority.elgamal,
                self.authority.auditoria,
                self.public_key
            )
            
            # Obtener votos válidos
            valid_votes = self.voting_center.get_valid_votes()
            
            if len(valid_votes) == 0:
                print("No hay votos para contar.")
                pausar()
                return
            
            print(f"Iniciando proceso de conteo...")
            print(f"   Total de votos a procesar: {len(valid_votes)}")
            
            # Realizar recuento homomórfico con mixnet
            yes_count, no_count = self.tallying_center.tally_votes(valid_votes)
            
            # Guardar resultados
            self.resultados = {
                'si': yes_count,
                'no': no_count
            }
            self.estadisticas = stats
            self.eleccion_cerrada = True
            
            print("¡Conteo completado exitosamente!")
            print("   Puedes ver los resultados en el menú principal.")
            
        except Exception as e:
            print(f"Error durante el conteo: {e}")
            import traceback
            traceback.print_exc()
        
        pausar()
    
    def ver_resultados(self):
        limpiar_pantalla()
        mostrar_titulo()
        print("═"*70)
        print("                    📊 RESULTADOS DE LA ELECCIÓN")
        print("═"*70)
        
        if not self.eleccion_cerrada or self.resultados is None:
            print("Los resultados aún no están disponibles.")
            print("   La elección debe cerrarse para ver los resultados.")
            pausar()
            return
        
        yes_count = self.resultados['si']
        no_count = self.resultados['no']
        total = yes_count + no_count
        
        print(f"Pregunta: {self.pregunta_votacion}")
        print("\n" + "─"*70)
        
        # Resultados
        yes_pct = (yes_count / total * 100) if total > 0 else 0
        no_pct = (no_count / total * 100) if total > 0 else 0
        
        print(f"\n  {'Opción':<20} {'Votos':<10} {'Porcentaje':<15} {'Gráfico':<20}")
        print("  " + "─"*65)
        
        # Barra de progreso para SÍ
        bar_length = 30
        yes_bar = "█" * int(yes_pct / 100 * bar_length)
        print(f"  {'SÍ':<20} {yes_count:<10} {yes_pct:>6.2f}%      {yes_bar}")
        
        # Barra de progreso para NO
        no_bar = "█" * int(no_pct / 100 * bar_length)
        print(f"  {'NO':<20} {no_count:<10} {no_pct:>6.2f}%      {no_bar}")
        
        print("  " + "─"*65)
        print(f"  {'TOTAL':<20} {total:<10} {'100.00%':>10}")
        
        # Ganador
        print("\n" + "─"*70)
        if yes_count > no_count:
            print("\n  🏆 RESULTADO: La propuesta fue APROBADA")
        elif no_count > yes_count:
            print("\n  🏆 RESULTADO: La propuesta fue RECHAZADA")
        else:
            print("\n  🏆 RESULTADO: EMPATE")
        
        # Estadísticas
        print("\n" + "─"*70)
        print("\n📊 Estadísticas:")
        print(f"   • Votantes registrados: {self.estadisticas['registered_voters']}")
        print(f"   • Votos emitidos: {self.estadisticas['total_votes']}")
        print(f"   • Votos válidos: {self.estadisticas['valid_votes']}")
        print(f"   • Votos rechazados: {self.estadisticas['rejected_votes']}")
        print(f"   • Participación: {self.estadisticas['participation_rate']:.2f}%")
        
        print("\n" + "─"*70)
        print("\n✅ Verificación de Auditoría:")
        self.authority.auditoria.verificar_integridad()
        
        pausar()
    
    def ver_estado_eleccion(self):
        """Muestra el estado actual de la elección"""
        limpiar_pantalla()
        mostrar_titulo()
        print("═"*70)
        print("                   📋 ESTADO DE LA ELECCIÓN")
        print("═"*70)
        
        if not self.eleccion_activa:
            print("No hay una elección activa en este momento.")
            pausar()
            return
        
        print(f"Pregunta: {self.pregunta_votacion}")
        print(f"   Opciones: SÍ / NO")
        
        print(f"Estado: {'CERRADA' if self.eleccion_cerrada else 'ACTIVA'}")
        
        if self.voting_center is not None:
            stats = self.voting_center.get_statistics()
            print(f"📊 Estadísticas actuales:")
            print(f"   • Votantes registrados: {stats['registered_voters']}")
            print(f"   • Votos válidos recibidos: {stats['valid_votes']}")
            print(f"   • Votos rechazados: {stats['rejected_votes']}")
            print(f"   • Participación: {stats['participation_rate']:.1f}%")
            
            # Mostrar votantes registrados
            if len(self.tokens) > 0:
                print(f"\n👥 Votantes registrados:")
                for i, voter_id in enumerate(list(self.tokens.keys())[:10], 1):
                    # Verificar si ya votó
                    token = self.tokens[voter_id].token
                    ha_votado = not self.authority.token_system.verify_token(token)[0] or \
                               self.authority.token_system.verify_token(token)[1] == "Token ya fue usado"
                    
                    estado = "✓ Votó" if ha_votado else "✗ Pendiente"
                    print(f"   {i:2d}. {voter_id:<30} {estado}")
                
                if len(self.tokens) > 10:
                    print(f"   ... y {len(self.tokens) - 10} más")
        else:
            print("Votantes aún no han sido registrados.")
        
        pausar()
    
    def acerca_del_sistema(self):
        """Muestra información sobre el sistema"""
        limpiar_pantalla()
        mostrar_titulo()
        print("═"*70)
        print("                   ℹ️  ACERCA DEL SISTEMA")
        print("═"*70)
        
        print("SISTEMA DE VOTACIÓN ELECTRÓNICA SEGURA")
        print("\nDesarrollado por:")
        print("  • Luis Cabarcas Romero (lcabarcase@uninorte.edu.co)")
        print("  • Ashley Mercado Defort (agmercado@uninorte.edu.co)")
        
        print("Proyecto Final - Criptografía")
        print("   Universidad del Norte")
        
        print("\n🛡️  CARACTERÍSTICAS DE SEGURIDAD:")
        print("\n  ✓ Privacidad Total")
        print("    Los votos individuales están cifrados con ElGamal")
        print("    Nadie puede ver cómo votó cada persona")
        
        print("\n  ✓ Verificabilidad")
        print("    Cada voto incluye una prueba NIZK (Zero-Knowledge)")
        print("    Se puede verificar que el voto es válido sin revelarlo")
        
        print("\n  ✓ Integridad")
        print("    Sistema de tokens previene votación doble")
        print("    Solo se cuentan votos válidos y autorizados")
        
        print("\n  ✓ Anonimato")
        print("    Mixnet rompe la relación entre votante y voto")
        print("    Imposible rastrear quién votó qué")
        
        print("\n  ✓ Auditoría")
        print("    Registro inmutable de todos los eventos")
        print("    Similar a blockchain para verificar integridad")
        
        print("\n🔢 TECNOLOGÍA:")
        print("  • Cifrado homomórfico ElGamal multiplicativo")
        print("  • Pruebas Zero-Knowledge (NIZK)")
        print("  • Sistema de tokens HMAC")
        print("  • Mixnet para anonimato")
        print("  • Cadena de auditoría inmutable")
        
        print("\n💡 ¿CÓMO FUNCIONA?")
        print("  1. El administrador crea una elección y registra votantes")
        print("  2. Cada votante recibe un token único de un solo uso")
        print("  3. Los votantes emiten votos cifrados con su token")
        print("  4. Los votos se mezclan para garantizar anonimato")
        print("  5. Se cuentan los votos usando propiedades homomórficas")
        print("  6. Solo se revela el total, nunca los votos individuales")
        
        pausar()
    
    def salir(self):
        """Cierra la aplicación"""
        limpiar_pantalla()
        mostrar_titulo()
        print("\n" + "═"*70)
        print("\n Gracias por usar el Sistema de Votación Segura")
        print("\n Tu privacidad y seguridad son nuestra prioridad")
        print("\n" + "═"*70 + "\n")


def main():
    """Función principal"""
    try:
        app = AplicacionVotacion()
        app.ejecutar()
    except KeyboardInterrupt:
        print("\n Aplicación interrumpida por el usuario.")
    except Exception as e:
        print(f"\n Error inesperado: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
