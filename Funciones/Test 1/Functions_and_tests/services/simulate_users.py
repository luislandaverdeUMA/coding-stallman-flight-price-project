

"""
Función: Simular usuarios
- Requiere autenticación y rol 'admin'
- Registra N simulaciones en la bitácora (HMAC encadenado)
- Bloquea tras demasiados intentos fallidos (anti fuerza bruta)
"""
from typing import Dict
from services.auth import AuthService, AuthorizationService
from services.audit import audit_log
from services.data import users

class SimularUsuariosService:
    def __init__(self, users_store: Dict[str, Dict]):
        self.auth = AuthService(max_failures=5)
        self.rbac = AuthorizationService(users_store)

    def simular_usuarios(self, usuario_id: str, token: str, count: int) -> Dict:
        # Validación de parámetros
        if count < 0 or count > 1000:
            raise ValueError("Parámetro 'count' fuera de rango")

        # Bloqueo por fuerza bruta
        if self.auth.blocked(usuario_id):
            raise PermissionError("Usuario bloqueado por demasiados intentos fallidos")

        # Autenticación
        if not self.auth.authenticate(usuario_id, token):
            raise PermissionError("Autenticación fallida")

        # Autorización (RBAC)
        self.rbac.require_role(usuario_id, {"admin"})

        # Simulación y auditoría
        for i in range(count):
            audit_log.append(actor=f"user{i}", action="simulate_login", details="")
        return {"ok": True, "simulated": count}
