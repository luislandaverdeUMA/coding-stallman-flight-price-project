import pytest
from cryptography.fernet import Fernet

from services import AntiGougingService, JWTAuth, CryptoBox


@pytest.fixture
def svc():
    jwt_auth = JWTAuth(secret="TEST_SECRET", ttl_seconds=60)
    crypto = CryptoBox(fernet_key=Fernet.generate_key())
    return AntiGougingService(jwt_auth=jwt_auth, crypto=crypto)


def test_autenticarUsuario_ok(svc):
    auth = svc.autenticarUsuario("user@example.com", "Passw0rd!", client_id="web-app")
    assert auth.token
    assert auth.user_id == "u1"
    assert auth.expires_at > 0


def test_autenticarUsuario_fail_password(svc):
    with pytest.raises(PermissionError):
        svc.autenticarUsuario("user@example.com", "WRONG", client_id="web-app")


def test_darPrecioAlta_ok_encrypts_and_stores(svc):
    auth = svc.autenticarUsuario("user@example.com", "Passw0rd!", client_id="web-app")
    ok = svc.darPrecioAlta(
        session_token=auth.token,
        client_id="web-app",
        price_payload={
            "flight_id": "IB1234",
            "source": "api_provider",
            "currency": "EUR",
            "price": 199.99,
        },
    )
    assert ok == "OK"
    assert len(svc._prices_encrypted) == 1

    # opcional: verificar que se puede desencriptar (prueba real)
    rec = svc.crypto.decrypt_json(svc._prices_encrypted[0])
    assert rec["user_id"] == "u1"
    assert rec["flight_id"] == "IB1234"
    assert rec["price"] == 199.99


def test_darPrecioAlta_fail_invalid_token(svc):
    with pytest.raises(Exception):
        svc.darPrecioAlta(
            session_token="bad.token.here",
            client_id="web-app",
            price_payload={
                "flight_id": "IB1234",
                "source": "api_provider",
                "currency": "EUR",
                "price": 199.99,
            },
        )


def test_darPrecioAlta_fail_bad_payload(svc):
    auth = svc.autenticarUsuario("user@example.com", "Passw0rd!", client_id="web-app")
    with pytest.raises(ValueError):
        svc.darPrecioAlta(
            session_token=auth.token,
            client_id="web-app",
            price_payload={
                "flight_id": "IB1234",
                "source": "api_provider",
                "currency": "EUR",
                "price": -5,  # inválido
            },
        )


def test_cerrarPerfilUsuario_ok_and_blocks_future_login(svc):
    auth = svc.autenticarUsuario("user@example.com", "Passw0rd!", client_id="web-app")
    closed = svc.cerrarPerfilUsuario(auth.token, client_id="web-app")
    assert closed == "CLOSED"

    # después de cerrar, no debería poder autenticar (usuario desactivado)
    with pytest.raises(PermissionError):
        svc.autenticarUsuario("user@example.com", "Passw0rd!", client_id="web-app")