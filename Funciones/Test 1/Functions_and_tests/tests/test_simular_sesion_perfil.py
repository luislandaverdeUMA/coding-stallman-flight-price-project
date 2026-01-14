

"""
STDD - Simular sesión desde un perfil:
- Solo admin (401/PermissionError si falla auth o si no admin)
- Registra todas las acciones en auditoría
- Cadena HMAC permanece válida
"""
import pytest
from services.simulate_profile import SimularSesionPerfilService
from services.auth import generate_token
from services.data import users
from services.audit import audit_log

@pytest.fixture
def service():
    audit_log.entries.clear()
    return SimularSesionPerfilService(users_store=users)

def test_admin_registra_acciones(service):
    admin = "admin@demo"
    token = generate_token(admin)
    acciones = ["login","view","compare"]
    res = service.simular_sesion_desde_perfil(admin, token, profile_id="perfilX", actions=acciones)
    assert res["actions"] == len(acciones)
    assert audit_log.verify_chain() is True

def test_auth_falla(service):
    with pytest.raises(PermissionError):
        service.simular_sesion_desde_perfil("admin@demo", "malo", "p", ["login"])

def test_rbac_falla_si_no_admin(service):
    analyst = "analyst@demo"
    token = generate_token(analyst)
    with pytest.raises(PermissionError):
        service.simular_sesion_desde_perfil(analyst, token, "p", ["login"])
