"""Utilidades criptográficas con gmpy2"""
import hashlib
import gmpy2


def is_prime(n, k=25):
    """Test de primalidad Miller-Rabin"""
    return gmpy2.is_prime(n, k)


def generate_safe_prime(bits):
    """Genera primo seguro p = 2q + 1"""
    print(f"Generando primo seguro de {bits} bits...")
    random_state = gmpy2.random_state()
    
    while True:
        q = gmpy2.mpz_urandomb(random_state, bits - 1)
        q = gmpy2.bit_set(q, bits - 2)
        q = q | 1
        q = gmpy2.next_prime(q)
        
        if q.bit_length() != bits - 1:
            continue
        
        p = 2 * q + 1
        if is_prime(p):
            print(f"  Primo seguro: p = {p}, q = {q}")
            return int(p), int(q)


def find_generator(p, q):
    """Encuentra generador del subgrupo de orden q en Z*_p"""
    print("Buscando generador del subgrupo...")
    random_state = gmpy2.random_state()
    p_mpz = gmpy2.mpz(p)
    q_mpz = gmpy2.mpz(q)
    
    while True:
        h = gmpy2.mpz_random(random_state, p_mpz - 2) + 2
        g = gmpy2.powmod(h, 2, p_mpz)
        if g != 1 and gmpy2.powmod(g, q_mpz, p_mpz) == 1:
            print(f"  Generador encontrado: g = {g}")
            return int(g)


def mod_inverse(a, m):
    """Calcula inverso multiplicativo de a módulo m"""
    try:
        return int(gmpy2.invert(a, m))
    except ZeroDivisionError:
        raise ValueError(f"El inverso modular de {a} módulo {m} no existe")


def hash_to_challenge(*elements):
    """Hash SHA-256 para transformación Fiat-Shamir"""
    hasher = hashlib.sha256()
    for element in elements:
        if isinstance(element, int):
            hasher.update(element.to_bytes((element.bit_length() + 7) // 8, 'big'))
        elif isinstance(element, str):
            hasher.update(element.encode('utf-8'))
        elif isinstance(element, bytes):
            hasher.update(element)
        else:
            hasher.update(str(element).encode('utf-8'))
    return int.from_bytes(hasher.digest(), 'big')


def discrete_log_small(g, h, p, max_value):
    """Logaritmo discreto por búsqueda exhaustiva para valores pequeños"""
    g_mpz = gmpy2.mpz(g)
    h_mpz = gmpy2.mpz(h)
    p_mpz = gmpy2.mpz(p)
    
    current = gmpy2.mpz(1)
    for x in range(max_value + 1):
        if current == h_mpz:
            return x
        current = (current * g_mpz) % p_mpz
    
    raise ValueError(f"No se encontró logaritmo discreto hasta {max_value}")
