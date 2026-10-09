#!/usr/bin/env python3
"""Bounded native decoy-search cancellation probe with public test data only."""

import os
import selectors
import subprocess
import sys
import time


def one_core():
    """One native worker suffices and keeps this probe's CPU use bounded."""
    allowed = os.sched_getaffinity(0)
    os.sched_setaffinity(0, {min(allowed)})


def main():
    child = subprocess.Popen(
        [sys.argv[1], "cancel"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        preexec_fn=one_core,
    )
    selector = selectors.DefaultSelector()
    selector.register(child.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + 45
    cancel_started = None
    try:
        while child.poll() is None:
            if time.monotonic() >= deadline:
                child.kill()
                child.wait()
                if cancel_started is None:
                    print("BLOCKED: candidate enumeration did not finish before the setup deadline")
                    return 2
                print("FAIL: search has not returned two seconds after its callback returned Cancelled")
                return 1
            for key, _ in selector.select(timeout=0.05):
                line = key.fileobj.readline()
                if not line:
                    continue
                if "CANCEL_REQUESTED" in line:
                    if cancel_started is None:
                        cancel_started = time.monotonic()
                        deadline = cancel_started + 2
                    # The implementation repeats this callback while joining the same worker.
                    continue
                print(line.rstrip())
        for line in child.stdout:
            print(line.rstrip())
        if child.returncode != 0:
            return child.returncode
        if cancel_started is None:
            print("FAIL: no cancellation callback was reached")
            return 1
        print("PASS: cancellation returned within the bounded deadline")
        return 0
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        selector.close()


if __name__ == "__main__":
    sys.exit(main())
