# TOOL-01: public fixtures and cases of the Python PTY test runtime.
"""Explicit coins and paths reach every CLI address-reference operation.

Only published public addresses are used; cases stop before Argon2 or
the missing-word search, at prompts that precede the work.
"""

import os
import sys

from .constants import (
    ADDRESS_ASKED,
    CANCELLED,
    COIN_ASKED,
    CONTAINER,
    CONTAINER_ASKED,
    CTRL_C,
    ENTER,
    PUBLIC_ETHEREUM_ADDRESS,
)
from .repair import CARD_ASKED, container_with
from .session import Session, run_with_output

PUBLIC_BITCOIN_ADDRESS = b"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
BITCOIN_PATH = "m/84'/0'/0'/0/7"
ETHEREUM_PATH = "m/44'/60'/0'/0/0"


def explicit_address_options_skip_questions_and_refuse_misplaced_options():
    """
    Rekey and both missing-word wallet references retain the exact path.
    """
    rekey = ("rekey", "--pim", "0", "--mem", "0", "--new-pim", "0",
             "--new-mem", "0", "--words", "24", "--confirm", "address",
             "--coin", "ethereum", "--path", ETHEREUM_PATH,
             "--passphrase-used", "yes", "--repair-words", "0",
             "--new-password", "own")
    session = Session(rekey, capped=sys.platform == "linux")
    session.wait_for(CONTAINER_ASKED)
    session.answer(CONTAINER.encode() + ENTER, b"Old container password")
    session.answer(b"test password\r", ADDRESS_ASKED)
    session.answer(PUBLIC_ETHEREUM_ADDRESS + ENTER, ETHEREUM_PATH.encode(),
                   b"BIP39 passphrase of the wallet")
    assert COIN_ASKED not in session.output, session.output
    assert b"only " + ETHEREUM_PATH.encode() in session.output, session.output
    session.close()
    for whose in (b"1\r", b"2\r"):
        session, reader = run_with_output(("decrypt", "--pim", "0", "--mem", "0",
                           "--coin", "bitcoin", "--path", BITCOIN_PATH),
                          redirected=True, term="dumb")
        session.wait_for(CONTAINER_ASKED)
        session.answer(container_with({1: "?"}) + ENTER, CARD_ASKED)
        session.answer(ENTER, b"No repair words: what do you know?")
        session.answer(whose, b"Address or master key fingerprint")
        if whose == b"1\r":
            session.answer(b"73c5da0a\r", b"belong to an address reference",
                           b"Address or master key fingerprint")
        session.answer(PUBLIC_BITCOIN_ADDRESS + ENTER, BITCOIN_PATH.encode())
        assert COIN_ASKED not in session.output, session.output
        assert b"only " + BITCOIN_PATH.encode() in session.output, session.output
        session.press(CTRL_C)
        assert session.drain_until_exit(10)
        code, settings = session.close()
        assert code == CANCELLED and settings == session.original, code
        os.close(reader)
    print("address options: rekey and both searches use the given coin and exact path")
