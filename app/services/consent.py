import hashlib

CONSENT_VERSION = "2026-01"

_MODE_LABEL = {
    "passive": "pasivo (rastreo y análisis de respuestas, sin payloads de ataque)",
    "active_safe": "activo no destructivo (peticiones de prueba de baja intensidad, sin explotación ni DoS)",
}


def consent_statement(hostname: str, mode: str) -> str:
    """Texto exacto que el auditor acepta. Se renderiza en el servidor y se guarda su SHA-256."""
    return (
        f"Declaro que dispongo de autorización ESCRITA, vigente y firmada por el titular del dominio "
        f"«{hostname}» para realizar pruebas de seguridad en modo {_MODE_LABEL[mode]}. "
        f"El alcance de esta prueba está contenido en dicha autorización y la referencia indicada "
        f"corresponde al documento que la acredita. Entiendo que esta declaración queda registrada "
        f"con mi identidad, fecha, hora y dirección IP, y que soy responsable de su veracidad."
    )


def statement_sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()
