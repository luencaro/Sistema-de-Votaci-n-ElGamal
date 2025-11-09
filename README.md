# Sistema de Votación ElGamal

Sistema de votación electrónica con **cifrado homomórfico ElGamal multiplicativo** y **pruebas NIZK** (Non-Interactive Zero-Knowledge).


## *Desarrollado por Luis Cabarcas Romero (<lcabarcase@uninorte.edu.co>) y Ashley Mercado Defort (<agmercado@uninorte.edu.co>)*

## ¿Qué hace?

Permite votar de forma **privada** y **verificable**:
- Los votos están **cifrados** (nadie puede ver votos individuales)
- Cada voto incluye una **prueba criptográfica** de validez
- Los votos se **acumulan sin descifrar** (homomorfismo)
- Sistema de **tokens** previene votación doble

## Instalación

### Dependencias del Sistema
```bash
# Fedora/RHEL
sudo dnf install gmp-devel mpfr-devel libmpc-devel
```

### Paquetes Python
```bash
python3 -m venv venv
source venv/bin/activate
pip install gmpy2
o usar requirements.txt
```

## Uso

**Importante**: Activar el entorno virtual primero:
```bash
source venv/bin/activate
```

Luego ejecutar:
```bash
python test/verify.py         # Verificación del sistema (6 tests)
python src/main.py            # Demostración completa (8 votantes)
python test/examples.py       # Ejemplos interactivos por componente
```

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

### 4. Tokens de Un Solo Uso
- Token = `HMAC(secret, voter_id || timestamp || nonce)`
- Se marca como usado después de votar
- Detecta intentos de voto doble

## Arquitectura

```
src/
├── crypto_utils.py      → Primitivas (primos seguros, generadores, gmpy2)
├── elgamal.py          → Sistema de cifrado + homomorfismo
├── nizk.py             → Generación y verificación de pruebas
├── token_system.py     → Gestión de tokens HMAC
├── voting_system.py    → Orquestación completa
│   ├─ VotingAuthority   (genera claves, registra votantes)
│   ├─ Voter             (cifra voto + genera prueba)
│   ├─ VotingCenter      (recibe y valida votos)
│   └─ TallyingCenter    (acumula y descifra)
└── main.py             → Demostración completa

test/
├── verify.py           → Suite de verificación (6 tests)
└── examples.py         → Ejemplos interactivos
```

## Optimizaciones

- **gmpy2**: Aritmética de precisión arbitraria (10-100x más rápido)
- Primos seguros de 128-512 bits (configurable)
- Búsqueda exhaustiva de log discreto (solo para sumas pequeñas)
