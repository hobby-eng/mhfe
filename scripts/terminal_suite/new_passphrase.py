# TOOL-01: Python PTY cases for native new-wallet input.
"""Raw BIP39 passphrase limits before either new-wallet draw mode."""

from .constants import CANCELLED, CANCELLED_SHOWN, CHOSEN_ASKED, ESCAPE
from .session import Session


def new_wallet_passphrases_are_bounded_before_drawing():
    """Both check choices retry long raw text before drawing."""
    expanding = ("\ufdfa" * 341 + "a").encode("utf-8")
    contracting = ("\uff21" * 341 + "aa").encode("utf-8")
    assert len(expanding) == 1024 and len(contracting) == 1025
    for checked in ("no", "yes"):
        session = Session(("new", "--pim", "0", "--wallet-check", checked))
        try:
            session.wait_for(b"passphrase of the new wallet")
            for oversized in (b"a" * 1025, contracting):
                session.answer(oversized + b"\r", b"Repeat the passphrase")
                session.answer(oversized + b"\r", b"passphrase is too long",
                               b"1025 bytes", b"passphrase of the new wallet")
            session.answer(expanding + b"\r", b"Repeat the passphrase")
            session.answer(expanding + b"\r", CHOSEN_ASKED)
            session.answer(ESCAPE, CANCELLED_SHOWN)
            assert session.drain_until_exit(10), "new: cancel did not finish"
            assert b"Drawing " not in session.output, "new: drew before wishes"
        finally:
            code, settings = session.close()
        assert code == CANCELLED, "new: input preflight changed cancellation"
        assert settings == session.original, "new: terminal settings changed"
    print("new: raw 1025-byte passphrases retry in both check modes; "
          "1024 raw bytes accept NFKD expansion before drawing")
