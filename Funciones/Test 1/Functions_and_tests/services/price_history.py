

"""
Función: Consultar el histórico de precios (traveler/analyst/admin).
- Autenticación con token determinista (demo): token = sha256(usuario_id)
- RBAC: deniega 'provider'
- Filtra en memoria por 'route' y rango de fechas (YYYY-MM-DD)
- Sin SQL -> robusto frente a strings maliciosos en 'route'
"""
from typing import List, Optional, Dict
from datetime import datetime
from services.auth import AuthService, AuthorizationService
from services.data import users, prices

class PriceHistoryService:
    def __init__(self):
        self.auth = AuthService()
        self.rbac = AuthorizationService(users)

    def consultar_historico(self, usuario_id: str, token: str,
                            route: str, start: Optional[str] = None, end: Optional[str] = None) -> List[Dict]:
        # Bloqueo por fuerza bruta
        if self.auth.blocked(usuario_id):
            raise PermissionError("Usuario bloqueado")

        # Autenticación
        if not self.auth.authenticate(usuario_id, token):
            raise PermissionError("Autenticación fallida")

        # RBAC: permite viajero/analyst/admin
        self.rbac.require_role(usuario_id, {"viajero", "analyst", "admin"})

        # Validación de fechas (si se proporcionan)
        start_dt = end_dt = None
        if start:
            try:
                start_dt = datetime.fromisoformat(start)
            except ValueError:
                raise ValueError("Formato de fecha inválido (start)")
        if end:
            try:
                end_dt = datetime.fromisoformat(end)
            except ValueError:
                raise ValueError("Formato de fecha inválido (end)")

        # Filtrado seguro en memoria (no hay SQL)
        data = [p for p in prices if p["route"] == route]

        if start_dt or end_dt:
            tmp = []
            for p in data:
                d = datetime.fromisoformat(p["date"])
                if start_dt and d < start_dt:
                    continue
                if end_dt and d > end_dt:
                    continue
                tmp.append(p)
            data = tmp

        return data
