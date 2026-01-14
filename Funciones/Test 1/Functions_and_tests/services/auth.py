
# -*- coding: utf-8 -*-
"""
Autenticación y autorización mínimas para STDD:
- AuthService: valida tokens (simulación) y controla intentos fallidos (anti fuerza bruta).
- AuthorizationService: verifica roles permitidos (RBAC).
- Utilidad generate_token(): token derivado del usuario (SHA-256) para pruebas.
"""
import hashlib
from typing import Dict

class AuthService:
    def __init__(self, max_failures: int = 5):
        self.failures: Dict[str, int] = {}  # contador de fallos por usuario
        self.max_failures = max_failures

    def authenticate(self, usuario_id: str, token: str) -> bool:
        """Devuelve True si el token coincide; en caso contrario incrementa fallos."""
        expected = hashlib.sha256(usuario_id.encode()).hexdigest()
        ok = (token == expected)
        if not ok:
            self.failures[usuario_id] = self.failures.get(usuario_id, 0) + 1
        return ok

    def blocked(self, usuario_id: str) -> bool:
        """Bloquea temporalmente tras demasiados fallos (anti fuerza bruta)."""
        return self.failures.get(usuario_id, 0) >= self.max_failures

def generate_token(usuario_id: str) -> str:
    """Token determinista para pruebas (NO usar en producción)."""
    return hashlib.sha256(usuario_id.encode()).hexdigest()

class AuthorizationService:
    def __init__(self, users_store: Dict[str, Dict[str, str]]):
        self.users = users_store

    def require_role(self, usuario_id: str, allowed: set[str]):
        user = self.users.get(usuario_id)
        role = user["role"] if user else None
        if role not in allowed:
            raise PermissionError("Acceso prohibido (RBAC)")
