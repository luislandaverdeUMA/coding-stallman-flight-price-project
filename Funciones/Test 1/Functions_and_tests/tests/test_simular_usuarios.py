"""
STDD - Simular usuarios:
- Autenticación: requiere token válido (PermissionError si falla)
- Anti fuerza bruta: tras demasiados fallos, bloquea
- RBAC: solo admin puede simular (PermissionError si no)
- Auditoría: cadena HMAC válida tras simular
"""
import pytest
from services.simulate_users import SimularUsuariosService
from services.auth import generate_token
from services.data import users
from services.audit import audit_log

@pytest.fixture
def service():
    # Reiniciar auditoría para pruebas limpias
    audit_log.entries.clear()
    return SimularUsuariosService(users_store=users)

def test_auth_valida_y_rbca_admin(service):
    admin = "admin@demo"
    token = generate_token(admin)
    res = service.simular_usuarios(admin, token, count=3)
    assert res["simulated"] == 3
    assert audit_log.verify_chain() is True

def test_auth_invalida(service):
    admin = "admin@demo"
    with pytest.raises(PermissionError):
        service.simular_usuarios(admin, token="token_malo", count=1)

def test_rbac_no_admin(service):
    trav = "traveler@demo"
    token = generate_token(trav)
    with pytest.raises(PermissionError):
        service.simular_usuarios(trav, token, count=1)

def test_fuerza_bruta_bloqueo(service):
    admin = "admin@demo"
    # 5 intentos fallidos -> bloqueado
    for _ in range(5):
        with pytest.raises(PermissionError):
            service.simular_usuarios(admin, token="incorrecto", count=1)
    # incluso con token correcto, debe seguir bloqueado
    with pytest.raises(PermissionError):
        service.simular_usuarios(admin, token=generate_token(admin), count=1)

def test_parametros_invalidos(service):
    admin = "admin@demo"
    token = generate_token(admin)
    with pytest.raises(ValueError):
        service.simular_usuarios(admin, token, count=-1)
