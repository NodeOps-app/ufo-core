import pytest
from pydantic import ValidationError
from ufo_ext_createos.guest import Request


def test_request_rejects_unknown_actions_and_fields() -> None:
    with pytest.raises(ValidationError):
        Request.model_validate({"action": "exec", "priviledged": True})
    with pytest.raises(ValidationError):
        Request.model_validate({"action": "arbitrary"})
    with pytest.raises(ValidationError):
        Request.model_validate({"action": "exec", "privileged": "false"})
