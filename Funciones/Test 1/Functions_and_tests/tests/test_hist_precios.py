

"""
STDD - Consultar histórico de precios:
- Autenticación requerida (token válido)
- RBAC: traveler/analyst/admin; provider denegado (403 -> PermissionError)
- Validación de fechas (YYYY-MM-DD); formato inválido -> ValueError
- Resiliente a ruta maliciosa (no hay SQL, filtrado en memoria)
"""
import pytest
from services.price_history import PriceHistoryService
from services.auth import generate_token

@pytest.fixture
def service():
    return PriceHistoryService()

def login_token(uid: str) -> str:
    return generate_token(uid)

def test_auth_valida_viajero_ok(service):
    viajero = "viajero@demo"
    token = login_token(viajero)
    data = service.consultar_historico(viajero, token, route="MAD-CDG")
    assert isinstance(data, list)

def test_rbac_provider_denegado(service):
    prov = "providor@demo"
    token = login_token(prov)
    with pytest.raises(PermissionError):
        service.consultar_historico(prov, token, route="MAD-CDG")

def test_fecha_invalida(service):
    analyst = "analyst@demo"
    token = login_token(analyst)
    with pytest.raises(ValueError):
        service.consultar_historico(analyst, token, route="MAD-CDG", start="fecha_mala")

def test_route_malicioso_no_revienta(service):
    analyst = "analyst@demo"
    token = login_token(analyst)
    ruta = "MAD-CDG; DROP TABLE users; --"
    data = service.consultar_historico(analyst, token, route=ruta)
    assert isinstance(data, list)
