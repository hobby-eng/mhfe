#!/usr/bin/env python3
"""Replay the retained AUD-014 baseline's independent mathematical witnesses."""

import hashlib
import json
import math
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
BASELINE_RECORD = ROOT / "docs/audits/AUD-014-evidence/baseline-stat-controls.log"
BASELINE_HEAD = "4c3a6909bced0f0907f61ae291b11bb6bb419689"
# The baseline was dirty. These original file hashes, rather than HEAD alone, identify the inputs.
BASELINE_SOURCE_SHA256 = {
    "src/word_wishes/statistics.rs": "c37e51afba891e1c7ae3f46e484e3e159357a2ef70aa52879b41cf84e655d23e",
    "src/word_wishes/known_answers.rs": "9c06ddfd6ef638ace96da6d5854a4158dbdace45fa7fa89b3ef5ea60ce433079",
}
BASELINE_VALUES = [0, 1, 1024, 2046, 2047]
BASELINE_THRESHOLD_SIGMAS = 5
BASELINE_MODEL_TAIL = 0.00010543348173268371
BASELINE_FIXED_CASE_POSITIONS = [1, 24]
BASELINE_STATISTICAL_POSITION = 12
WORD_BITS = 11
WORDS = 1 << WORD_BITS
POSITION_BINS = 24
SAMPLE_COUNT = 20_000
GAMMA_EPSILON = 1e-14
GAMMA_MINIMUM = 1e-300
GAMMA_ITERATIONS = 10_000


def gamma_tail(shape, value):
    """Regularized upper incomplete gamma, using series or continued fraction."""
    scale = math.exp(shape * math.log(value) - value - math.lgamma(shape))
    if value < shape + 1:
        term = 1 / shape
        total = term
        for iteration in range(1, GAMMA_ITERATIONS + 1):
            term *= value / (shape + iteration)
            total += term
            if abs(term) <= abs(total) * GAMMA_EPSILON:
                return max(0.0, 1 - total * scale)
    else:
        denominator = value + 1 - shape
        forward = 1 / GAMMA_MINIMUM
        backward = 1 / denominator
        fraction = backward
        for iteration in range(1, GAMMA_ITERATIONS + 1):
            numerator = -iteration * (iteration - shape)
            denominator += 2
            backward = numerator * backward + denominator
            if abs(backward) < GAMMA_MINIMUM:
                backward = GAMMA_MINIMUM
            forward = denominator + numerator / forward
            if abs(forward) < GAMMA_MINIMUM:
                forward = GAMMA_MINIMUM
            backward = 1 / backward
            change = backward * forward
            fraction *= change
            if abs(change - 1) <= GAMMA_EPSILON:
                return fraction * scale
    raise AssertionError("gamma-tail calculation did not converge")


def exchange_middle_bits(number):
    # Offsets two and three, counting the highest bit as offset zero.
    first = 1 << (WORD_BITS - 1 - 2)
    second = 1 << (WORD_BITS - 1 - 3)
    if bool(number & first) != bool(number & second):
        return number ^ first ^ second
    return number


def main():
    assert all(exchange_middle_bits(number) == number for number in BASELINE_VALUES)
    hidden_changes = sum(exchange_middle_bits(number) != number for number in range(WORDS))
    assert hidden_changes == WORDS // 2

    freedom = POSITION_BINS - 1
    threshold = freedom + BASELINE_THRESHOLD_SIGMAS * math.sqrt(2 * freedom)
    probability = gamma_tail(freedom / 2, threshold / 2)
    # Gamma tails with integer shape have a finite closed-form independent check.
    assert abs(gamma_tail(1, 3) - math.exp(-3)) < 1e-13
    assert abs(gamma_tail(2, 3) - math.exp(-3) * 4) < 1e-13
    # The odd degrees of freedom also permit an independent erfc-plus-recurrence calculation.
    half_value = threshold / 2
    reference = math.erfc(math.sqrt(half_value))
    for numerator in range(1, freedom, 2):
        shape = numerator / 2
        reference += math.exp(shape * math.log(half_value) - half_value - math.lgamma(shape + 1))
    assert abs(probability - reference) < 1e-14
    assert abs(probability - BASELINE_MODEL_TAIL) < 1e-14

    absent = (1 - 1 / WORDS) ** POSITION_BINS
    singleton = POSITION_BINS / WORDS * (1 - 1 / WORDS) ** (POSITION_BINS - 1)
    conditional_repeats = 1 - singleton / (1 - absent)
    insertion_repeats = 1 - (1 - 1 / WORDS) ** (POSITION_BINS - 1)
    conditional_sigma = math.sqrt(conditional_repeats * (1 - conditional_repeats) / SAMPLE_COUNT)

    captured_record = None
    if BASELINE_RECORD.exists():
        record_bytes = BASELINE_RECORD.read_bytes()
        record = json.loads(record_bytes)
        assert record["audit"] == "AUD-014"
        assert record["source_sha256"] == BASELINE_SOURCE_SHA256
        assert record["middle_bit_exchange"]["unaffected_existing_values"] == BASELINE_VALUES
        assert record["middle_bit_exchange"]["changed_word_values_out_of_2048"] == hidden_changes
        assert abs(record["position_chi_square"]["actual_model_tail_probability"] - probability) < 1e-14
        captured_record = {
            "path": str(BASELINE_RECORD.relative_to(ROOT)),
            "sha256": hashlib.sha256(record_bytes).hexdigest(),
            "verified": True,
        }

    output = {
        "audit": "AUD-014",
        "method": "replay of captured baseline integer and probability calculations; no current production code or mutant executed",
        "baseline_head": BASELINE_HEAD,
        "baseline_dirty": True,
        "baseline_source_sha256": BASELINE_SOURCE_SHA256,
        "optional_captured_record": captured_record,
        "middle_bit_exchange": {
            "unaffected_existing_values": BASELINE_VALUES,
            "changed_word_values_out_of_2048": hidden_changes,
            "example_input": 256,
            "example_mutated_output": exchange_middle_bits(256),
            "fixed_startup_case_positions": BASELINE_FIXED_CASE_POSITIONS,
            "fixed_statistical_position": BASELINE_STATISTICAL_POSITION,
            "scope": "a setter fault confined to position 2 also avoids fixed KAT positions 1 and 24 and draw-test position 12",
        },
        "position_chi_square": {
            "degrees_of_freedom": freedom,
            "baseline_formula": "df + 5 * sqrt(2 * df)",
            "existing_threshold": threshold,
            "actual_model_tail_probability": probability,
            "verified_by_independent_erfc_recurrence": True,
            "claimed_approximate_tail_probability": 1e-6,
            "limitation": "the chi-square distribution is an asymptotic model of multinomial counts",
        },
        "anywhere_multiplicity": {
            "uniform_conditioned_duplicate_probability": conditional_repeats,
            "forced_random_insertion_duplicate_probability": insertion_repeats,
            "difference_in_standard_deviations_at_20000": (insertion_repeats - conditional_repeats) / conditional_sigma,
            "limitation": "the BIP39 checksum word is approximated as an independent uniform word",
        },
    }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
