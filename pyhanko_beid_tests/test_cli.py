from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner
from pyhanko.cli import cli_root
from pyhanko.cli.plugin_api import register_signing_plugin
from pyhanko.sign import SimpleSigner

INPUT_PATH = 'input.pdf'
SIGNED_OUTPUT_PATH = 'output.pdf'
DATA_DIR = Path('pyhanko_beid_tests') / 'data'


def _write_config(config: dict, fname: str = 'pyhanko.yml'):
    with open(fname, 'w') as outf:
        yaml.dump(config, outf)


def _const(v):
    def f(*_args, **_kwargs):
        return v

    return f


def _read_minimal():
    with open(DATA_DIR / 'minimal.pdf', 'rb') as f:
        return f.read()


MINIMAL = _read_minimal()


@pytest.fixture(scope="function", autouse=True)
def cli_runner():

    from pyhanko_beid.cli import BEIDPlugin
    register_signing_plugin(BEIDPlugin)

    runner = CliRunner()
    with runner.isolated_filesystem():
        with open(INPUT_PATH, 'wb') as outf:
            outf.write(MINIMAL)
        yield runner


class _DummyManager:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return


SELF_SIGN = SimpleSigner.load(
    DATA_DIR / 'selfsigned.key.pem',
    DATA_DIR / 'selfsigned.cert.pem',
    key_passphrase=b'secret',
)


def test_cli_addsig_beid(cli_runner, monkeypatch):
    from pyhanko_beid import beid

    monkeypatch.setattr(
        beid, 'open_beid_session', value=_const(_DummyManager())
    )
    monkeypatch.setattr(beid, 'BEIDSigner', value=_const(SELF_SIGN))
    with open('libbeidpkcs11-mock', 'wb') as mocklib:
        mocklib.write(b"\x00")
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'beid',
            '--lib',
            'libbeidpkcs11-mock',
            INPUT_PATH,
            'output.pdf',
        ],
    )
    assert not result.exception, result.output


def test_cli_addsig_beid_with_setup(cli_runner, monkeypatch):
    from pyhanko_beid import beid

    monkeypatch.setattr(
        beid, 'open_beid_session', value=_const(_DummyManager())
    )
    monkeypatch.setattr(beid, 'BEIDSigner', value=_const(SELF_SIGN))

    _write_config({'beid-module-path': 'libbeidpkcs11-mock'})
    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'beid',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert not result.exception, result.output


def test_cli_beid_lib_mandatory(cli_runner, monkeypatch):
    from pyhanko_beid import beid

    monkeypatch.setattr(
        beid, 'open_beid_session', value=_const(_DummyManager())
    )
    monkeypatch.setattr(beid, 'BEIDSigner', value=_const(SELF_SIGN))

    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'beid',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert result.exit_code == 1
    assert '--lib option is mandatory' in result.output


def test_cli_beid_pkcs11_error(cli_runner, monkeypatch):
    from pkcs11 import PKCS11Error

    from pyhanko_beid import beid

    def _throw(*_args, **_kwargs):
        raise PKCS11Error

    monkeypatch.setattr(beid, 'open_beid_session', value=_throw)

    _write_config({'beid-module-path': 'blah'})

    result = cli_runner.invoke(
        cli_root,
        [
            'sign',
            'addsig',
            '--field',
            'Sig1',
            'beid',
            INPUT_PATH,
            SIGNED_OUTPUT_PATH,
        ],
    )
    assert result.exit_code == 1
    assert 'PKCS#11 error' in result.output
