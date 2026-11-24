import pytest

from app import create_app
from config import Settings
from mailer import MailSendError

KEY = "clave-de-prueba"
HEADERS = {"X-Service-Key": KEY}


class FakeMailer:
    def __init__(self, error=None):
        self.sent, self.error = [], error

    def send(self, message):
        if self.error:
            raise self.error
        self.sent.append(message)


def make(error=None, **overrides):
    mailer = FakeMailer(error)
    settings = Settings(api_key=KEY, sender="liga@example.com", **overrides)
    return create_app(settings, mailer).test_client(), mailer


def body(**changes):
    data = {"to": ["a@gmail.com", "b@gmail.com"], "subject": "Nuevo partido: X vs Y", "html": "<p>Hola <b>mundo</b></p>"}
    data.update(changes)
    return data


def test_envio_exitoso():
    client, mailer = make()
    response = client.post("/api/notifications/send", json=body(), headers=HEADERS)
    assert response.status_code == 200
    assert response.get_json() == {"message": "Correo enviado."}
    message = mailer.sent[0]
    assert message["To"] == "a@gmail.com, b@gmail.com"
    assert message["Subject"] == "Nuevo partido: X vs Y"
    assert message.get_body(("html",)).get_content().strip() == "<p>Hola <b>mundo</b></p>"
    assert "Hola mundo" in message.get_body(("plain",)).get_content()


def test_sin_clave_401():
    client, _ = make()
    assert client.post("/api/notifications/send", json=body()).status_code == 401


def test_clave_extra_400():
    client, _ = make()
    assert client.post("/api/notifications/send", json=body(extra=1), headers=HEADERS).status_code == 400


@pytest.mark.parametrize("changes", [
    {"to": []},
    {"to": ["no-es-correo"]},
    {"to": ["a@gmail.com", "A@gmail.com"]},
    {"to": [f"u{i}@gmail.com" for i in range(21)]},
    {"to": "a@gmail.com"},
    {"subject": "Hola\nBcc: x@y.com"},
    {"subject": "   "},
    {"subject": "x" * 201},
    {"html": ""},
    {"html": 5},
])
def test_datos_invalidos_400(changes):
    client, mailer = make()
    response = client.post("/api/notifications/send", json=body(**changes), headers=HEADERS)
    assert response.status_code == 400
    assert not mailer.sent


def test_gmail_falla_502():
    client, _ = make(MailSendError("X"))
    assert client.post("/api/notifications/send", json=body(), headers=HEADERS).status_code == 502


def test_limite_por_destinatario_429():
    client, _ = make(rate_per_recipient=1)
    assert client.post("/api/notifications/send", json=body(), headers=HEADERS).status_code == 200
    assert client.post("/api/notifications/send", json=body(), headers=HEADERS).status_code == 429


def test_2fa_sigue_funcionando():
    client, mailer = make()
    response = client.post(
        "/api/2fa/send",
        json={"email": "a@gmail.com", "code": "123456", "expires_minutes": 10},
        headers=HEADERS,
    )
    assert response.status_code == 200
    assert mailer.sent[0]["To"] == "a@gmail.com"
