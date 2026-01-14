

"""
Bitácora de auditoría con HMAC encadenado (tamper-evident).
"""
import hmac, hashlib
from typing import List, Dict

class AuditLog:
    def __init__(self, secret: bytes = b"audit-secret"):
        self.secret = secret
        self.entries: List[Dict] = []

    def append(self, actor: str, action: str, details: str):
        prev = self.entries[-1]["hash"] if self.entries else ""
        msg = f"{actor}|{action}|{details}|{prev}".encode()
        h = hmac.new(self.secret, msg, hashlib.sha256).hexdigest()
        self.entries.append({"actor": actor, "action": action, "details": details, "hash": h})

    def verify_chain(self) -> bool:
        prev = ""
        for e in self.entries:
            msg = f"{e['actor']}|{e['action']}|{e['details']}|{prev}".encode()
            h = hmac.new(self.secret, msg, hashlib.sha256).hexdigest()
            if h != e["hash"]:
                return False
            prev = e["hash"]
        return True

# Instancia global simple para demo (compartida entre servicios)
audit_log = AuditLog()
