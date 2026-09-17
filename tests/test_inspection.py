import pytest

from agentgate.security.inspection import inspect, redact


@pytest.mark.parametrize(
    "payload",
    [
        {"api_key": "sensitive-value"},
        {"nested": {"password": "sensitive-value"}},
        {"Authorization": "Bearer abcdefghijklmnop"},
        {"content": "api_key=sensitive-value"},
        {"content": "postgres://user:password@database.example/db"},
        {"content": "contact customer@example.com"},
        {"content": "111-22-3333"},
        {"card": 4111111111111111},
    ],
)
def test_secret_or_pii_detected_and_redacted(payload):
    assert inspect(payload)
    assert redact(payload) != payload
    assert redact(redact(payload)) == redact(payload)


def test_security_metric_names_are_not_secret_values():
    metrics = {"secret_persistence_count": 0, "pii_persistence_count": 0, "secret_leakage_cases": 6}
    assert redact(metrics) == metrics


@pytest.mark.parametrize(
    "key", ["clientSecret", "accessToken", "aws_secret_access_key", "dbPassword", "credentials"]
)
def test_common_credential_field_names(key):
    assert redact({key: "opaque-value-123"})[key] == "[REDACTED]"
    assert inspect({key: "opaque-value-123"})[0]["category"] == "secret"
