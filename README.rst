python-beid-plugin
==================


Introduction
^^^^^^^^^^^^

This package provides a plugin for `pyHanko <https://github.com/MatthiasValvekens/pyHanko>`_'s
PDF signing CLI. The implementation is a very thin convenience wrapper around the PKCS#11
functionality included within the "core" pyHanko library.

It used to be part of pyHanko's core feature set until version 0.22.0 for historical reasons.


Installation
^^^^^^^^^^^^

Assuming you are installing with ``pip``, running
``pip install pyhanko-beid-plugin`` will install both pyHanko and the plugin.
If you already have a working pyHanko install, take care to ensure that
the plugin is installed in the same Python environment.

PyHanko makes use of Python's package entry point mechanism to discover
plugins, so installing both side-by-side should suffice. To test whether
everything works, run ``pyhanko sign addsig`` and verify that ``beid``
appears in the list of subcommands.


Installation troubleshooting
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you're having issues getting the plugin autodection to work, you can
also add the following snippet to your PyHanko configuration file:

.. code-block:: yaml

   plugins:
     - pyhanko_beid.cli:BEIDPlugin


This will work as long as you ensure that ``pyhanko_beid`` is importable.



Signing a PDF file using a Belgian eID card
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To sign a PDF file using your eID card and pyHanko's CLI (with this plugin),
use the ``beid`` subcommand to ``addsig``, with the ``--lib`` parameter to
tell pyHanko where to look for the eID PKCS#11 library.

.. note::
    Of course, you can also use the ``pkcs11`` subcommand, but ``beid`` provides an extra layer
    of convenience.

On Linux, it is named ``libbeidpkcs11.so`` and can usually be found under
``/usr/lib`` or ``/usr/local/lib``.
On macOS, it is named ``libbeidpkcs11.dylib``, and can similarly be found under
``/usr/local/lib``.
The Windows version is typically installed to ``C:\Windows\System32`` and is
called ``beidpkcs11.dll``.


On Linux, this boils down to the following:

.. code-block:: bash

    pyhanko sign addsig --field Sig1 beid \
        --lib /path/to/libbeidpkcs11.so input.pdf output.pdf

On all platforms, the eID middleware will prompt you to enter your PIN to create
the signature.


.. warning::
    This command will produce a non-repudiable signature using the 'Signature'
    certificate on your eID card (as opposed to the 'Authentication'
    certificate). These signatures are legally equivalent to
    a normal "wet" signature wherever they are allowed, so use them with care.

    In particular, you should only allow software you trust\ [#disclaimer]_
    to use the 'Signature' certificate!


.. warning::
    You should also be aware that your national registry number
    (rijksregisternummer, no. de registre national) is embedded into the
    metadata of the signature certificate on your eID card\ [#nnserial]_.
    As such, it can also be **read off from any digital signature you create**.
    While national registry numbers aren't secret per se, they are nevertheless
    often considered sensitive personal information, so you may want to be
    careful where you send documents containing your eID signature or that
    of someone else.

.. [#disclaimer]
    This obviously also applies to pyHanko itself.

.. [#nnserial]
    In the current implementation, the certificate's serial number is in fact
    equal to the holder's national registry number.
