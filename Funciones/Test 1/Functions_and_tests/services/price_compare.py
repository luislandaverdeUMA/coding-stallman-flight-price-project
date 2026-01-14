

"""
Función: Comparar precios entre perfiles (analyst/admin).
Seguridad:
- Autenticación determinista de demo: token = sha256(usuario_id)
- RBAC: solo 'analyst' o 'admin' pueden comparar
Privacidad:
- Devuelve únicamente promedios por etiqueta de perfil (sin PII)
Resiliencia:
- Filtrado en memoria por 'route' (no hay SQL), por lo que cadenas maliciosas no ejecutan nada
"""
from typing import Dict
from services.auth import AuthService, AuthorizationService
from services.data import users, prices

class PriceCompareService:
    def __init__(self):
        self.auth = AuthService()
        self.rbac = AuthorizationService(users)

    def comparar(self, usuario_id: str, token: str, route: str) -> Dict:
        # Bloqueo por fuerza bruta (si hubo demasiados fallos previos)
        if self.auth.blocked(usuario_id):
            raise PermissionError("Usuario bloqueado")

        # Autenticación
        if not self.auth.authenticate(usuario_id, token):
            raise PermissionError("Autenticación fallida")

        # RBAC: solo analyst/admin
        self.rbac.require_role(usuario_id, {"analyst", "admin"})

        # Agregación sin PII: claves = etiquetas de perfil (A/B/...), valores = promedios
        rows = [p for p in prices if p["route"] == route]
        profiles: Dict[str, list] = {}
        for r in rows:
            profiles.setdefault(r["profile"], []).append(r["price"])

        medians = {k: (sum(v)/len(v)) for k, v in profiles.items()} if profiles else {}
        return {"medians": medians}
