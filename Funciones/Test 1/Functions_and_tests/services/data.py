
# -*- coding: utf-8 -*-
"""
Datos de demo en memoria (usuarios y precios).
"""
from typing import Dict, List

users: Dict[str, Dict] = {
    "admin@demo":   {"pwd": "admin",   "role": "admin"},
    "analyst@demo": {"pwd": "analyst", "role": "analyst"},
    "viajero@demo":{"pwd": "viajero","role": "viajero"},
    "providor@demo":{"pwd": "providor","role": "providor"},
}

# Registros de precios de ejemplo (para histórico/compare)
prices: List[Dict] = [
    {"route": "MAD-CDG", "date": "2025-01-01", "price": 100.0, "profile": "A"},
    {"route": "MAD-CDG", "date": "2025-01-05", "price": 120.0, "profile": "B"},
    {"route": "MAD-CDG", "date": "2025-01-20", "price": 115.0, "profile": "A"},
    {"route": "AGP-MAD", "date": "2025-01-10", "price": 80.0,  "profile": "A"},
]
