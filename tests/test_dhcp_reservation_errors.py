"""DHCP input rejections stay actionable without leaking backend diagnostics."""

from types import SimpleNamespace

import httpx
import pytest

from tests.test_multi_service_ui import admin_client

PAYLOAD = {"name": "device", "mac": "aa:bb:cc:dd:ee:01", "address": "192.0.2.5"}


def rejecting_agent(response):
    def post(_path, _payload):
        response.raise_for_status()

    return SimpleNamespace(
        post=post,
        get=lambda _path: [],
        read_only=lambda: False,
    )


@pytest.mark.parametrize("status", [400, 403, 409, 422])
def test_agent_input_error_is_visible_and_preserves_open_form(tmp_path, status):
    app, client = admin_client(tmp_path)
    message = "IP address 192.0.2.5 is already reserved for legacy. Update or delete it."
    app.extensions["netadmin_dhcp"] = rejecting_agent(
        httpx.Response(
            status,
            json={"error": message},
            request=httpx.Request("POST", "https://synthetic/reservations"),
        )
    )
    response = client.post("/dhcp", data=PAYLOAD)
    assert response.status_code == status
    assert message in response.text
    assert 'role="alert"' in response.text
    assert '<details class="card advanced-group" open>' in response.text
    for value in PAYLOAD.values():
        assert f'value="{value}"' in response.text
    assert b"dhcp.reservation.upsert" not in client.get("/audit").data


@pytest.mark.parametrize(
    "body",
    ["private HTML response", "[]", '{"error": 123}', '{"error": ""}'],
)
def test_non_message_agent_errors_use_actionable_fallback(tmp_path, body):
    app, client = admin_client(tmp_path)
    app.extensions["netadmin_dhcp"] = rejecting_agent(
        httpx.Response(
            409,
            text=body,
            request=httpx.Request("POST", "https://synthetic/reservations"),
        )
    )
    response = client.post("/dhcp", data=PAYLOAD)
    assert response.status_code == 409
    assert "Check the reservations below" in response.text
    assert "private HTML response" not in response.text


def test_agent_message_is_escaped_and_bounded(tmp_path):
    app, client = admin_client(tmp_path)
    app.extensions["netadmin_dhcp"] = rejecting_agent(
        httpx.Response(
            409,
            json={"error": "<script>alert(1)</script>" + "x" * 600},
            request=httpx.Request("POST", "https://synthetic/reservations"),
        )
    )
    response = client.post("/dhcp", data=PAYLOAD)
    assert "<script>alert(1)</script>" not in response.text
    assert "&lt;script&gt;" in response.text
    assert "x" * 501 not in response.text


@pytest.mark.parametrize("status", [401, 500, 502])
def test_backend_server_and_authentication_details_remain_private(tmp_path, status):
    app, client = admin_client(tmp_path)
    app.extensions["netadmin_dhcp"] = rejecting_agent(
        httpx.Response(
            status,
            json={"error": "synthetic-private-backend-diagnostic"},
            request=httpx.Request("POST", "https://synthetic/reservations"),
        )
    )
    response = client.post("/dhcp", data=PAYLOAD)
    assert response.status_code == 502
    assert "synthetic-private-backend-diagnostic" not in response.text
