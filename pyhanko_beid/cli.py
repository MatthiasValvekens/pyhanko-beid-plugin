import contextlib
from typing import ContextManager, List, Optional

import click
from pyhanko.cli._ctx import CLIContext
from pyhanko.cli.commands.signing.pkcs11_cli import (
    UNAVAIL_MSG,
    pkcs11_available,
)
from pyhanko.cli.config import CLIConfig
from pyhanko.cli.plugin_api import SigningCommandPlugin
from pyhanko.cli.utils import logger, readable_file
from pyhanko.sign import Signer


class BEIDPlugin(SigningCommandPlugin):
    subcommand_name = 'beid'
    help_summary = 'use Belgian eID to sign'
    unavailable_message = UNAVAIL_MSG

    def is_available(self) -> bool:
        return pkcs11_available

    def click_options(self) -> List[click.Option]:
        return [
            click.Option(
                ('--lib',),
                help='path to libbeidpkcs11 library file',
                type=readable_file,
                required=False,
            ),
            click.Option(
                ('--slot-no',),
                help='specify PKCS#11 slot to use',
                required=False,
                type=int,
                default=None,
            ),
        ]

    def create_signer(
        self, context: CLIContext, **kwargs
    ) -> ContextManager[Signer]:
        return _beid_signer_context(context, **kwargs)


def _beid_signer_context(ctx: CLIContext, lib, slot_no):
    import pkcs11

    from pyhanko_beid import beid

    module_path: str
    if not lib:
        cli_config: Optional[CLIConfig] = ctx.config
        beid_module_path: Optional[str] = None
        if cli_config is not None:
            beid_module_path = cli_config.raw_config.get(
                'beid-module-path', None
            )
        if beid_module_path is None:
            raise click.ClickException(
                "The --lib option is mandatory unless beid-module-path is "
                "provided in the configuration file."
            )
        module_path = beid_module_path
    else:
        module_path = lib

    @contextlib.contextmanager
    def manager():
        try:
            session = beid.open_beid_session(module_path, slot_no=slot_no)
        except pkcs11.PKCS11Error as e:
            logger.error("PKCS#11 error", exc_info=e)
            raise click.ClickException(
                f"PKCS#11 error: [{type(e).__name__}] {e}"
            )

        with session:
            yield beid.BEIDSigner(session)

    return manager()
