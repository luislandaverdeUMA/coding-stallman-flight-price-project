# services.py
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import jwt  # pip install PyJWT
from cryptography.fernet import Fernet  # pip install cryptography

logger = logging.getLogger("AntiGouging")
logger.setLevel(logging.INFO)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ---------- Models ----------
@dataclass
class AuthResult:
    token: str
    user_id: str
    expires_at: int


# ---------- Security helpers ----------
class JWTAuth:
    def __init__(self, secret: str, issuer: str = "antigouging", ttl_seconds: int = 3600):
        self.secret = secret
        self.issuer = issuer
        self.ttl_seconds = ttl_seconds

    def issue(self, user_id: str, client_id: str) -> AuthResult:
        now = int(time.time())
        exp = now + self.ttl_seconds
        payload = {
            "sub": user_id,
            "cid": client_id,
            "iss": self.issuer,
            "iat": now,
            "exp": exp,
        }
        token = jwt.encode(payload, self.secret, algorithm="HS256")
        return AuthResult(token=token, user_id=user_id, expires_at=exp)

    def verify(self, token: str, client_id: str) -> Dict[str, Any]:
        payload = jwt.decode(token, self.secret, algorithms=["HS256"], issuer=self.issuer)
        if payload.get("cid") != client_id:
            raise PermissionError("Token no corresponde al client_id.")
        return payload


class CryptoBox:
    """Encriptación simétrica (Fernet). Guarda FERNET_KEY como variable de entorno/secret."""
    def __init__(self, fernet_key: bytes):
        self.f = Fernet(fernet_key)

    def encrypt_json(self, data: Dict[str, Any]) -> str:
        import json
        raw = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return self.f.encrypt(raw).decode("utf-8")

    def decrypt_json(self, token: str) -> Dict[str, Any]:
        import json
        raw = self.f.decrypt(token.encode("utf-8"))
        return json.loads(raw.decode("utf-8"))


def validate_price_payload(payload: Dict[str, Any]) -> None:
    """Validación de datos (mínima pero real)."""
    required = ["flight_id", "source", "currency", "price"]
    for k in required:
        if k not in payload:
            raise ValueError(f"Falta campo requerido: {k}")

    if not isinstance(payload["flight_id"], str) or len(payload["flight_id"]) < 3:
        raise ValueError("flight_id inválido")

    if payload["currency"] not in {"EUR", "USD", "GBP"}:
        raise ValueError("currency inválida")

    price = payload["price"]
    if not (isinstance(price, int) or isinstance(price, float)) or price <= 0:
        raise ValueError("price inválido")

    if not isinstance(payload["source"], str) or len(payload["source"]) < 2:
        raise ValueError("source inválido")


# ---------- Service ----------
class AntiGougingService:
    """
    3 funciones del proyecto:
      - autenticarUsuario() -> JWT + logging
      - darPrecioAlta() -> JWT + validación + encriptación
      - cerrarPerfilUsuario() -> JWT + logging
    """

    def __init__(self, jwt_auth: JWTAuth, crypto: CryptoBox):
        self.jwt_auth = jwt_auth
        self.crypto = crypto

        # Simulación de “DB”
        self._users: Dict[str, Dict[str, Any]] = {
            "u1": {"email": "user@example.com", "password": "Passw0rd!", "active": True}
        }
        self._prices_encrypted: list[str] = []

    # ---- Function 1: Access Control + Auditability ----
    def autenticarUsuario(self, email: str, password: str, client_id: str) -> AuthResult:
        if not EMAIL_RE.match(email):
            logger.warning("AUTH_FAIL invalid_email client_id=%s email=%s", client_id, email)
            raise ValueError("Email inválido")

        user_id = None
        for uid, u in self._users.items():
            if u["email"].lower() == email.lower() and u["active"]:
                user_id = uid
                break

        if not user_id or self._users[user_id]["password"] != password:
            logger.warning("AUTH_FAIL bad_credentials client_id=%s email=%s", client_id, email)
            raise PermissionError("Credenciales incorrectas")

        auth = self.jwt_auth.issue(user_id=user_id, client_id=client_id)
        logger.info("AUTH_OK user_id=%s client_id=%s exp=%s", auth.user_id, client_id, auth.expires_at)
        return auth

    # ---- Function 2: Secure Data Handling + Encryption + Integrity ----
    def darPrecioAlta(self, session_token: str, client_id: str, price_payload: Dict[str, Any]) -> str:
        # 1) Autenticación (JWT)
        claims = self.jwt_auth.verify(session_token, client_id=client_id)
        user_id = claims["sub"]

        # 2) Validación de datos
        validate_price_payload(price_payload)

        # 3) Encriptación antes de “persistir”
        record = {
            "user_id": user_id,
            "ts": int(time.time()),
            **price_payload,
        }
        encrypted = self.crypto.encrypt_json(record)
        self._prices_encrypted.append(encrypted)

        logger.info("PRICE_ADD_OK user_id=%s client_id=%s flight_id=%s source=%s",
                    user_id, client_id, price_payload["flight_id"], price_payload["source"])
        return "OK"

    # ---- Function 3: Account Closure + Auditability ----
    def cerrarPerfilUsuario(self, session_token: str, client_id: str) -> str:
        claims = self.jwt_auth.verify(session_token, client_id=client_id)
        user_id = claims["sub"]

        if user_id not in self._users or not self._users[user_id]["active"]:
            logger.warning("CLOSE_FAIL user_not_found user_id=%s client_id=%s", user_id, client_id)
            raise ValueError("Usuario no existe o ya está desactivado")

        self._users[user_id]["active"] = False
        logger.info("CLOSE_OK user_id=%s client_id=%s", user_id, client_id)
        return "CLOSED"


# ---------- Example usage (para pruebas rápidas) ----------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    jwt_auth = JWTAuth(secret="CHANGE_ME_SUPER_SECRET", ttl_seconds=3600)
    crypto = CryptoBox(fernet_key=Fernet.generate_key())

    svc = AntiGougingService(jwt_auth=jwt_auth, crypto=crypto)

    auth = svc.autenticarUsuario("user@example.com", "Passw0rd!", client_id="web-app")
    svc.darPrecioAlta(
        session_token=auth.token,
        client_id="web-app",
        price_payload={"flight_id": "IB1234", "source": "api_provider", "currency": "EUR", "price": 199.99},
    )
    svc.cerrarPerfilUsuario(auth.token, client_id="web-app")