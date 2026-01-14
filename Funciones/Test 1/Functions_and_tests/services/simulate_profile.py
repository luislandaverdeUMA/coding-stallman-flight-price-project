

"""
Función: Simular sesión desde un perfil (solo admin).
- Requiere autenticación (token = sha256(usuario_id) en esta demo)
- Aplica RBAC: solo 'admin' puede simular
- Registra cada acción en la bitácora de auditoría (HMAC encadenado)
"""

from typing import List, Dict
from services.auth import AuthService, AuthorizationService
from services.audit import audit_log

class SimularSesionPerfilService:
    def __init__(self, users_store: Dict[str, Dict]):
        self.auth = AuthService()
        self.rbac = AuthorizationService(users_store)

    def simular_sesion_desde_perfil(self, usuario_id: str, token: str,
                                    profile_id: str, actions: List[str]) -> Dict:
        # Bloqueo por fuerza bruta (si hubo demasiados fallos previos)
        if self.auth.blocked(usuario_id):
            raise PermissionError("Usuario bloqueado")

        # Autenticación
        if not self.auth.authenticate(usuario_id, token):
            raise PermissionError("Autenticación fallida")

        # Autorización (RBAC)
        self.rbac.require_role(usuario_id, {"admin"})

        # Registrar acciones simuladas en auditoría (tamper-evident)
        for act in actions:
            audit_log.append(actor=f"profile:{profile_id}", action="simulate_action", details=act)

        return {"ok": True, "actions": len(actions)}
