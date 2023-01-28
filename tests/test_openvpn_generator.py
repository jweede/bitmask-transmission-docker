import pathlib
from unittest import mock
import sys

import pytest

here = pathlib.Path(__file__).resolve().parent
expected_dir = here / "expected_ovpns"

try:
    import openvpn_generator
except ImportError:
    scripts_path = here.joinpath("../docker_scripts").resolve()
    sys.path.insert(0, str(scripts_path))
    import openvpn_generator


@pytest.mark.vcr()
@mock.patch("builtins.input")
def test_openvpn_generator_output(minput: mock.MagicMock, tmp_path, monkeypatch):
    minput.side_effect = [
        "10",
        "1",
        "3",
    ]
    monkeypatch.chdir(tmp_path)
    openvpn_generator.main()

    assert openvpn_generator.providers
    assert openvpn_generator.gateways
    assert sorted(openvpn_generator.openvpn_configurations.keys()) == [
        "calyx",
        "riseup",
    ]

    (output_path,) = tmp_path.joinpath("bitmask_ovpns").glob("*.ovpn")
    expected_path = expected_dir / output_path.name
    if expected_path.exists():
        assert output_path.read_text() == expected_path.read_text()
    else:
        expected_path.write_bytes(output_path.read_bytes())
