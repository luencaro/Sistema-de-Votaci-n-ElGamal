# Sistema de Votación ElGamal

Sistema de votación electrónica con **cifrado homomórfico ElGamal multiplicativo** y **pruebas NIZK** (Non-Interactive Zero-Knowledge).


## *Desarrollado por Luis Cabarcas Romero (<lcabarcase@uninorte.edu.co>) y Ashley Mercado Defort (<agmercado@uninorte.edu.co>)*

## ¿Qué hace?

Permite votar de forma **privada**, **anónima** y **verificable**:
- Los votos están **cifrados** (nadie puede ver votos individuales)
- Cada voto incluye una **prueba criptográfica** de validez (NIZK)
- Los votos se **acumulan sin descifrar** (homomorfismo)
- **Mixnet** rompe la trazabilidad votante-voto (re-cifrado y mezcla)
- Sistema de **tokens** previene votación doble
- **Auditoría inmutable** registra todos los eventos (blockchain-like)

## Instalación

### Dependencias del Sistema

#### Linux (Fedora/RHEL)
```bash
sudo dnf install gmp-devel mpfr-devel libmpc-devel
```

#### Windows
1. Descargar e instalar **Visual Studio Build Tools** o **MinGW-w64**
2. Opción más fácil: usar **wheels precompilados**:
   ```bash
   pip install gmpy2
   ```
3. Si falla, descargar wheel desde [Christoph Gohlke's packages](https://www.lfd.uci.edu/~gohlke/pythonlibs/#gmpy)

#### macOS
```bash
brew install gmp mpfr libmpc
```

### Paquetes Python

#### Linux/macOS
```bash
python3 -m venv venv
source venv/bin/activate
pip install gmpy2
# o usar: pip install -r requirements.txt
```

#### Windows (PowerShell)
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install gmpy2
# o usar: pip install -r requirements.txt
```

#### Windows (CMD)
```cmd
python -m venv venv
venv\Scripts\activate.bat
pip install gmpy2
```

## Uso

### Activar el Entorno Virtual

#### Linux/macOS
```bash
source venv/bin/activate
```

#### Windows (PowerShell)
```powershell
.\venv\Scripts\Activate.ps1
```

#### Windows (CMD)
```cmd
venv\Scripts\activate.bat
```

### Ejecutar el Sistema

Una vez activado el entorno virtual:

```bash
# Verificación rápida del sistema (6 tests de integración)
python test/verify.py

# Demostración completa con 8 votantes
python src/main.py

# Ejemplos interactivos por componente
python test/examples.py

# Suite completa de pruebas unitarias (27 tests)
python test/test_voting_system.py
```

**Nota para Windows**: Si `python` no funciona, intenta con `py` o `python3`

## Cómo Funciona

### 1. Cifrado ElGamal Multiplicativo
Cada voto `b ∈ {0,1}` se cifra como `(v, e)`:
```
v = g^β mod p
e = u^β · g^b mod p
```
- `β` es aleatorio único por voto
- `g` es generador público, `u = g^α` clave pública
- `α` es la clave privada (solo autoridad)

### 2. Pruebas NIZK
Cada voto incluye prueba de que cifrado contiene **0 OR 1**:
- **Protocolo Sigma disjuntivo** con Fiat-Shamir
- Verificable sin revelar el voto
- Imposible falsificar

### 3. Acumulación Homomórfica
Los votos se suman **sin descifrar**:
```
(v*, e*) = (∏vᵢ mod p, ∏eᵢ mod p)
```
Descifrar `(v*, e*)` → `g^suma` → recuperar `suma` por log discreto

### 4. Mixnet (Mezcla de Votos)
Rompe el vínculo votante-voto:
- **Permutación aleatoria** de los votos cifrados
- **Re-cifrado**: `(v', e') = (v·g^r, e·u^r) mod p`
- Genera prueba ZKP de mezcla correcta
- Imposible rastrear qué votante emitió qué voto

### 5. Sistema de Auditoría
Registro inmutable de eventos electorales:
- **Cadena de hashes** tipo blockchain
- Cada evento enlaza al anterior: `hash(evento_i) = f(hash(evento_i-1), datos_i)`
- Tipos: SETUP, REGISTRO, VOTO, MEZCLA, CONTEO
- **Verificación de integridad**: detecta cualquier alteración

### 6. Tokens de Un Solo Uso
- Token = `HMAC(secret, voter_id || timestamp || nonce)`
- Se marca como usado después de votar
- Detecta intentos de voto doble

## Arquitectura

```
src/
├── crypto_utils.py      → Primitivas (primos seguros, generadores, gmpy2)
├── elgamal.py          → Sistema de cifrado + homomorfismo
├── nizk.py             → Generación y verificación de pruebas NIZK
├── token_system.py     → Gestión de tokens HMAC
├── mixnet.py           → Mezcla y re-cifrado de votos (anonimato)
├── auditoria.py        → Sistema de auditoría con cadena de hashes
├── voting_system.py    → Orquestación completa
│   ├─ VotingAuthority   (genera claves, registra votantes)
│   ├─ Voter             (cifra voto + genera prueba)
│   ├─ VotingCenter      (recibe y valida votos)
│   └─ TallyingCenter    (mezcla, acumula y descifra)
└── main.py             → Demostración completa con 8 votantes

test/
├── verify.py           → Suite de verificación (6 tests de integración)
├── examples.py         → Ejemplos interactivos por componente
└── test_voting_system.py → 27 pruebas unitarias completas
```

## Optimizaciones

- **gmpy2**: Aritmética de precisión arbitraria (10-100x más rápido)
- Primos seguros de 128-512 bits (configurable)
- Búsqueda exhaustiva de log discreto (solo para sumas pequeñas)
