# Guía Rápida para Usuarios

## Inicio Rápido

### Ejecutar la Aplicación

```bash
python src/user_app.py
```

### Para el Administrador de la Elección

1. **Iniciar la aplicación** y seleccionar opción `1` (Modo Administrador)

2. **Crear una elección nueva** (opción `1`)
   - Ingresa la pregunta para la votación
   - Ejemplo: "¿Estás de acuerdo con extender el horario de clases?"
   - El sistema generará automáticamente las claves criptográficas

3. **Registrar votantes** (opción `2`)
   - Ingresa los IDs de los votantes (uno por línea)
   - Ejemplos: `Juan_Perez`, `votante_001`, `estudiante_123`
   - Presiona Enter en una línea vacía para terminar
   - **IMPORTANTE**: Guarda los tokens generados (opción de guardar en archivo)

4. **Distribuir tokens**
   - Los tokens se guardan automáticamente en un archivo `.txt`
   - Envía a cada votante su ID y token correspondiente de forma segura
   - Cada token solo puede usarse UNA VEZ

5. **Monitorear la votación** (opción `4`)
   - Ver cuántos votantes han participado
   - Ver participación en tiempo real

6. **Cerrar y contar votos** (opción `3`)
   - Cuando decidas cerrar la votación
   - El sistema cuenta automáticamente usando criptografía homomórfica
   - Los resultados se calculan sin revelar votos individuales

### Para los Votantes

1. **Recibir credenciales**
   - El administrador te proporcionará:
     - Tu ID de votante
     - Tu token único de votación

2. **Iniciar la aplicación** y seleccionar opción `2` (Modo Votante)

3. **Autenticación**
   - Ingresa tu ID de votante
   - Ingresa tu token de votación

4. **Emitir voto**
   - Lee la pregunta
   - Selecciona `1` para SÍ o `2` para NO
   - Confirma tu selección

5. **Confirmación**
   - Recibirás confirmación de que tu voto fue cifrado y registrado
   - Tu voto es completamente privado y anónimo

### Ver Resultados (Todos)

1. Seleccionar opción `3` desde el menú principal

2. Ver:
   - Resultados finales con porcentajes
   - Gráficos de barras
   - Estadísticas de participación
   - Verificación de auditoría

## Características de Seguridad

### Privacidad

- Cada voto está cifrado con ElGamal
- Nadie puede ver votos individuales, ni siquiera el administrador

### Verificabilidad

- Cada voto incluye una prueba matemática (NIZK)
- Cualquiera puede verificar que los votos son válidos

### Integridad

- Los tokens previenen votación doble
- Solo votos válidos son contados

### Anonimato

- Mixnet rompe la relación votante-voto
- Imposible rastrear quién votó qué

### Auditoría

- Todos los eventos quedan registrados
- Cadena de auditoría inmutable (tipo blockchain)

## 💡 Preguntas Frecuentes

**P: ¿Puedo votar dos veces?**
R: No. Cada token solo funciona una vez. El segundo intento será rechazado automáticamente.

**P: ¿Alguien puede ver mi voto?**
R: No. Tu voto está cifrado y solo se revela el conteo total final.

**P: ¿Qué pasa si pierdo mi token?**
R: Debes contactar al administrador. Los tokens no pueden recuperarse por seguridad.

**P: ¿Puedo cambiar mi voto después de emitirlo?**
R: No. Una vez confirmado, el voto es final y no puede modificarse.

**P: ¿Cómo sé que el sistema es seguro?**
R: El sistema usa criptografía ElGamal con pruebas Zero-Knowledge (NIZK) verificables matemáticamente.

**P: ¿Cuánto tiempo toma el conteo?**
R: Depende del número de votos, pero típicamente menos de un minuto incluso con cientos de votos.

## Solución de Problemas

### Error: "No module named 'gmpy2'"

```bash
pip install gmpy2
```

### Error: "Token inválido"

- Verifica que copiaste el token completo sin espacios
- Asegúrate de usar el token correcto para tu ID

### Error: "Token ya fue usado"

- Ya votaste anteriormente
- Cada persona solo puede votar una vez

### La aplicación no inicia

1. Verifica que estés en el directorio correcto
2. Intenta: `python3 src/user_app.py` o `py src/user_app.py`
