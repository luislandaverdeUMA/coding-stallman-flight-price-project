

"""
STDD - Comparar precios (seguridad y privacidad):
- Autenticación: token válido requerido (PermissionError si falla)
- RBAC: solo analyst/admin (viajero/providor -> PermissionError)
- Sin PII: devolver únicamente métricas agregadas por etiquetas de perfil
- Resiliencia: ruta maliciosa no debe romper ni ejecutar nada
"""
import pytest
from services.price_compare import PriceCompareService
from services.auth import generate_token

@pytest.fixture
def service():
    return PriceCompareService()

def test_auth_valida_analyst_ok(service):
    tok = generate_token("analyst@demo")
    res = service.comparar("analyst@demo", tok, route="MAD-CDG")
    assert isinstance(res, dict)
    assert "medians" in res
    assert isinstance(res["medians"], dict)

def test_auth_invalida(service):
    with pytest.raises(PermissionError):
        service.comparar("analyst@demo", "token_malo", route="MAD-CDG")

def test_rbac_traveler_denegado(service):
    tok = generate_token("viajero@demo")
    with pytest.raises(PermissionError):
        service.comparar("viajero@demo", tok, route="MAD-CDG")

def test_rbac_provider_denegado(service):
    tok = generate_token("providor@demo")
    with pytest.raises(PermissionError):
        service.comparar("providor@demo", tok, route="MAD-CDG")

def test_privacidad_sin_pii(service):
    tok = generate_token("admin@demo")
    res = service.comparar("admin@demo", tok, route="MAD-CDG")
    # Las claves deben ser etiquetas de perfil (A/B/...) y no PII (emails/IDs)
    assert all("@" not in k for k in res["medians"].keys())

def test_ruta_maliciosa_no_revienta(service):
    tok = generate_token("admin@demo")
    ruta = "MAD-CDG; DROP TABLE users; --"
    res = service.comparar("admin@demo", tok, route=ruta)
    assert isinstance(res, dict)
    assert "medians" in res
