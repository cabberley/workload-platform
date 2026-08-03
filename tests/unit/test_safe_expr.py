"""Security + correctness tests for the sandboxed expression evaluator (shared.safe_expr).

A reviewer WILL attack this: the evaluator must accept ONLY a tiny allowlisted grammar and reject
every escape (attribute/subscript/call/comprehension/lambda/dunder/f-string/walrus/non-allowlisted
name) fail-closed, and must never crash at evaluation time (div-by-zero/type => None).
"""
from __future__ import annotations

import pytest

from shared.safe_expr import (
    MAX_EXPR_LEN,
    TELEMETRY_EXPR_NAMES,
    UnsafeExpressionError,
    compile_expression,
    validate_expression,
)

_NAMES = TELEMETRY_EXPR_NAMES


def _ev(source: str, **env: float) -> bool | None:
    return compile_expression(source, allowed_names=_NAMES).evaluate(env)


# --------------------------------------------------------------------------------------
# Allowed grammar evaluates correctly
# --------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("source", "env", "expected"),
    [
        ("value > threshold", {"value": 10, "threshold": 5}, True),
        ("value > threshold", {"value": 3, "threshold": 5}, False),
        ("avg >= 5 and max < 100", {"avg": 5, "max": 40}, True),
        ("avg >= 5 and max < 100", {"avg": 5, "max": 400}, False),
        ("not (min < 0)", {"min": 2}, True),
        ("1 < avg < 10", {"avg": 5}, True),  # chained comparison
        ("1 < avg < 10", {"avg": 50}, False),
        ("value + 2 * 3 > threshold", {"value": 1, "threshold": 6}, True),
        ("-value < 0", {"value": 5}, True),
        ("count == 3 or sum > 100", {"count": 3, "sum": 1}, True),
        ("rate > 0", {"rate": 0.5}, True),
        ("(avg + max) / 2 > threshold", {"avg": 10, "max": 30, "threshold": 15}, True),
    ],
)
def test_allowed_grammar_evaluates(source: str, env: dict[str, float], expected: bool) -> None:
    assert _ev(source, **env) is expected


def test_validate_expression_accepts_allowed() -> None:
    assert validate_expression("avg > threshold", allowed_names=_NAMES) == []


# --------------------------------------------------------------------------------------
# Every disallowed construct fails to COMPILE (fail-closed)
# --------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "source",
    [
        "__import__('os')",              # call + dunder name
        "value.__class__",               # attribute access + dunder
        "avg.bit_length()",              # attribute + call
        "value()",                       # call
        "min(value, 1)",                 # call on an allowlisted name
        "data[0]",                       # subscript (and non-allowlisted name)
        "[x for x in range(3)]",         # comprehension
        "lambda: 1",                     # lambda
        "value if avg else max",         # conditional expression
        "os",                            # name not in allowlist
        "value := 1",                    # walrus
        "f'{value}'",                    # f-string
        "'string'",                      # string literal
        "True",                          # boolean literal (numeric literals only)
        "None",                          # None literal
        "value % 2",                     # modulo not in arithmetic allowlist
        "value ** 2",                    # power not allowed
        "{1: 2}",                        # dict
        "[1, 2]",                        # list
        "(1, 2)",                        # tuple
        "1e400 > value",                 # non-finite numeric literal (inf)
        "value & 1",                     # bitwise not allowed
        "",                              # empty
    ],
)
def test_disallowed_constructs_fail_closed(source: str) -> None:
    with pytest.raises(UnsafeExpressionError):
        compile_expression(source, allowed_names=_NAMES)
    assert validate_expression(source, allowed_names=_NAMES)  # non-empty error list


def test_name_not_in_caller_allowlist_rejected() -> None:
    # 'rate' is telemetry-allowlisted but a caller can pass a narrower set.
    with pytest.raises(UnsafeExpressionError):
        compile_expression("rate > 0", allowed_names=frozenset({"value", "threshold"}))


def test_oversized_expression_rejected() -> None:
    big = " + ".join(["value"] * (MAX_EXPR_LEN // 2)) + " > threshold"
    with pytest.raises(UnsafeExpressionError):
        compile_expression(big, allowed_names=_NAMES)


def test_deeply_nested_expression_rejected() -> None:
    nested = "not " * 30 + "value"  # 30 nested unary nodes exceeds the depth bound
    with pytest.raises(UnsafeExpressionError):
        compile_expression(nested, allowed_names=_NAMES)


# --------------------------------------------------------------------------------------
# Runtime safety: never crash — undefined => None (no detection)
# --------------------------------------------------------------------------------------
def test_division_by_zero_is_none_not_crash() -> None:
    assert _ev("value / count > 1", value=10, count=0) is None


def test_missing_name_at_eval_is_none() -> None:
    # 'rate' passes the allowlist but is absent from env (e.g. uncomputable) => no detection.
    assert _ev("rate > 0", value=1, threshold=1) is None


# --------------------------------------------------------------------------------------
# MED1 — an undefined/missing name makes the WHOLE expression undecidable (None), through
# every operator including `not`/`and`/`or`, comparisons and arithmetic (never fabricate True).
# --------------------------------------------------------------------------------------
def test_not_of_undefined_name_is_none_not_true() -> None:
    assert _ev("not rate", value=1, threshold=1) is None


@pytest.mark.parametrize(
    "source",
    [
        "not rate",                  # unary not
        "rate > 1",                  # comparison
        "rate and value > 0",        # boolean and (undefined left)
        "value > 0 or rate < 1",     # boolean or (undefined right, no short-circuit)
        "rate + value > 1",          # arithmetic
        "-rate < 0",                 # unary minus
        "value < rate < 10",         # chained comparison
    ],
)
def test_undefined_operand_yields_none_through_every_operator(source: str) -> None:
    assert _ev(source, value=5, threshold=1) is None  # 'rate' absent from env


def test_name_bound_to_non_finite_is_none() -> None:
    assert _ev("value > threshold", value=float("inf"), threshold=1) is None
    assert _ev("value > threshold", value=float("nan"), threshold=1) is None


# --------------------------------------------------------------------------------------
# MED-A — a chained comparison must not short-circuit past an undefined operand.
# --------------------------------------------------------------------------------------
def test_not_chained_comparison_with_undefined_operand_is_none() -> None:
    # First pair (value > threshold) is already false, but `rate` is absent ⇒ undecidable, so the
    # whole comparison is None and `not None` stays None (never flips to True).
    assert _ev("not (value > threshold < rate)", value=1, threshold=2) is None


def test_chained_comparison_undefined_later_operand_is_none() -> None:
    # max < avg is false; without the fix the chain would return False without inspecting `rate`.
    assert _ev("max < avg < rate", max=5, avg=1) is None


def test_chained_comparison_fully_defined_unchanged() -> None:
    assert _ev("min < avg < max", min=1, avg=2, max=3) is True
    assert _ev("min < avg < max", min=1, avg=5, max=3) is False  # second pair false, all defined
    assert _ev("value > threshold", value=5, threshold=1) is True  # single comparison unchanged


# --------------------------------------------------------------------------------------
# MED2 — numeric overflow: huge literals fail closed at compile; overflow to inf at eval is
# undecidable (never fabricates a detection).
# --------------------------------------------------------------------------------------
def test_huge_integer_literal_rejected_not_crash() -> None:
    huge = "9" * 400 + " > value"  # ~400-digit int overflows float() — must fail closed, not crash
    with pytest.raises(UnsafeExpressionError):
        compile_expression(huge, allowed_names=_NAMES)


def test_float_literal_near_ceiling_rejected() -> None:
    # A literal whose square overflows (e.g. 1e308) is rejected up-front.
    with pytest.raises(UnsafeExpressionError):
        compile_expression("1e308 * 1e308 > value", allowed_names=_NAMES)


def test_arithmetic_overflow_is_none_not_true() -> None:
    # An in-bounds product that overflows to inf is undecidable, never fabricates True.
    assert _ev("1e300 * 1e300 > value", value=1) is None


def test_evaluate_returns_bool_for_defined() -> None:
    result = _ev("value > threshold", value=5, threshold=1)
    assert result is True and isinstance(result, bool)


def test_evaluator_uses_no_builtins() -> None:
    # A pure-source audit: the sandbox never calls eval/exec/compile builtins.
    import pathlib

    source = pathlib.Path(
        pathlib.Path(__file__).resolve().parents[2] / "src" / "shared" / "safe_expr.py"
    ).read_text(encoding="utf-8")
    for banned in ("eval(", "exec(", "compile("):
        assert banned not in source
