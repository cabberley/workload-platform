"""A pure, sandbox-safe boolean expression evaluator over a vetted, allowlisted AST.

Detection packs (content, not code) may carry a small boolean ``expression`` (e.g.
``avg > threshold and max < 900``) that COMPILES to a pure detector at load time. This module is
the security boundary for that feature: it NEVER uses ``eval``/``exec``/``compile`` on the raw
string with real builtins. Instead it:

1. parses the source with ``ast.parse(source, mode="eval")`` (syntax only — no evaluation);
2. walks the tree and REJECTS (fail-closed) any node type or name that is not on a tiny
   allowlist — attribute access, subscripts, calls, comprehensions, lambdas, f-strings, walrus,
   starred, dunder names, and names outside the caller's allowlist all fail to compile;
3. bounds source length, tree depth and node count so a pathological pack cannot exhaust
   resources;
4. evaluates the vetted tree against a plain ``{name: number}`` environment with **no**
   ``__builtins__`` and **no** callables in scope. A division-by-zero, a type error or a missing
   name at evaluation time yields ``None`` (no detection) rather than raising — fail-closed.

## Grammar (exactly what is allowed)

    expr        := boolexpr
    boolexpr    := boolexpr ('and' | 'or') boolexpr
                 | 'not' boolexpr
                 | comparison
                 | arith
    comparison  := arith (('<' | '<=' | '>' | '>=' | '==' | '!=') arith)+   # chained allowed
    arith       := arith ('+' | '-' | '*' | '/') arith
                 | ('+' | '-') arith
                 | NUMBER                     # finite int/float literal only
                 | NAME                       # must be in the caller's allowlist

Everything else is rejected. Boolean literals (``True``/``False``), strings, ``None``, containers,
attribute/subscript/call/comprehension/lambda/f-string/walrus/starred nodes are all disallowed.

The module is intentionally dependency-free (``ast`` + ``math`` only) and knows nothing about
Azure or any module, so both the pack schema gate (``packs_engine.schema``) and the AIOps detector
compiler (``modules.aiops.detectors``) can share this one audited implementation.
"""
from __future__ import annotations

import ast
import math
from collections.abc import Mapping
from dataclasses import dataclass

# The telemetry expression vocabulary: the ONLY names a telemetry-pack expression may reference.
# ``value``/``threshold`` mirror the single-sample rule fields; the rest are the pure window
# aggregates exposed by ``modules.aiops.detectors``. Shared here (rather than in aiops) so the
# pure pack-schema gate can validate an expression without importing a module.
TELEMETRY_EXPR_NAMES: frozenset[str] = frozenset(
    {"value", "threshold", "avg", "max", "min", "count", "sum", "last", "rate"}
)

# Resource bounds — a pack expression is a tiny predicate, never a program.
MAX_EXPR_LEN = 500
MAX_EXPR_DEPTH = 25
MAX_EXPR_NODES = 120
# Reject literals whose magnitude is near the float ceiling: they compile fine but the smallest
# arithmetic (``lit * lit``) overflows to ``inf`` and would fabricate a comparison. Kept well below
# ``sys.float_info.max`` (~1.8e308) so any realistic threshold still fits.
MAX_EXPR_LITERAL = 1e300

# Allowlisted AST operator/node classes. Anything not enumerated here fails closed.
_ALLOWED_BOOL_OPS = (ast.And, ast.Or)
_ALLOWED_UNARY_OPS = (ast.Not, ast.UAdd, ast.USub)
_ALLOWED_BIN_OPS = (ast.Add, ast.Sub, ast.Mult, ast.Div)
_ALLOWED_CMP_OPS = (ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.Eq, ast.NotEq)


class UnsafeExpressionError(ValueError):
    """Raised when a source expression is malformed, oversized, or uses a disallowed construct."""


@dataclass(frozen=True)
class SafeExpression:
    """A compiled, vetted expression. ``evaluate`` is pure and never raises."""

    source: str
    allowed_names: frozenset[str]
    _tree: ast.Expression

    def evaluate(self, env: Mapping[str, float]) -> bool | None:
        """Evaluate against ``env`` (name -> number). Returns the boolean result, or ``None`` if
        evaluation is undefined — fail-closed: an undefined result is *no* detection, never a crash.

        Undefined includes: a referenced name absent from ``env`` or bound to a non-finite value, a
        division-by-zero, a numeric overflow to ``inf``, or a type error. Undefinedness propagates
        through **every** operator (``not``/``and``/``or``, comparisons, arithmetic), so any single
        undefined operand makes the whole expression undecidable — e.g. ``not rate`` with ``rate``
        absent is ``None`` (no detection), never ``True``.
        """
        try:
            result = _eval_node(self._tree.body, env)
        except (ZeroDivisionError, TypeError, ValueError, OverflowError, KeyError):
            return None
        if result is None:
            return None
        return bool(result)


def compile_expression(source: str, *, allowed_names: frozenset[str]) -> SafeExpression:
    """Parse, bound and allowlist-validate ``source``. Raise :class:`UnsafeExpressionError` if it
    is not a safe boolean expression over ``allowed_names``. Never evaluates the expression.
    """
    if not isinstance(source, str):
        raise UnsafeExpressionError("expression must be a string")
    if not source.strip():
        raise UnsafeExpressionError("expression is empty")
    if len(source) > MAX_EXPR_LEN:
        raise UnsafeExpressionError(f"expression exceeds {MAX_EXPR_LEN} characters")
    try:
        tree = ast.parse(source, mode="eval")
    except (SyntaxError, ValueError) as exc:  # ValueError e.g. null bytes
        raise UnsafeExpressionError(f"expression does not parse: {exc}") from exc

    for count, _node in enumerate(ast.walk(tree), start=1):
        if count > MAX_EXPR_NODES:
            raise UnsafeExpressionError(f"expression exceeds {MAX_EXPR_NODES} AST nodes")
    depth = _depth(tree.body)
    if depth > MAX_EXPR_DEPTH:
        raise UnsafeExpressionError(f"expression nesting exceeds depth {MAX_EXPR_DEPTH}")

    _validate(tree.body, allowed_names)
    return SafeExpression(source=source, allowed_names=frozenset(allowed_names), _tree=tree)


def validate_expression(source: str, *, allowed_names: frozenset[str]) -> list[str]:
    """Non-raising wrapper for the schema gate: ``[]`` if safe, else one human-readable error."""
    try:
        compile_expression(source, allowed_names=allowed_names)
    except UnsafeExpressionError as exc:
        return [str(exc)]
    return []


def _depth(node: ast.AST) -> int:
    children = list(ast.iter_child_nodes(node))
    if not children:
        return 1
    return 1 + max(_depth(child) for child in children)


def _validate(node: ast.AST, allowed_names: frozenset[str]) -> None:
    """Reject any node/operator/name not on the allowlist. Fail-closed on the FIRST violation."""
    if isinstance(node, ast.BoolOp):
        if not isinstance(node.op, _ALLOWED_BOOL_OPS):
            raise UnsafeExpressionError("disallowed boolean operator")
        for value in node.values:
            _validate(value, allowed_names)
        return
    if isinstance(node, ast.UnaryOp):
        if not isinstance(node.op, _ALLOWED_UNARY_OPS):
            raise UnsafeExpressionError("disallowed unary operator")
        _validate(node.operand, allowed_names)
        return
    if isinstance(node, ast.BinOp):
        if not isinstance(node.op, _ALLOWED_BIN_OPS):
            raise UnsafeExpressionError("disallowed arithmetic operator")
        _validate(node.left, allowed_names)
        _validate(node.right, allowed_names)
        return
    if isinstance(node, ast.Compare):
        for op in node.ops:
            if not isinstance(op, _ALLOWED_CMP_OPS):
                raise UnsafeExpressionError("disallowed comparison operator")
        _validate(node.left, allowed_names)
        for comparator in node.comparators:
            _validate(comparator, allowed_names)
        return
    if isinstance(node, ast.Name):
        if not isinstance(node.ctx, ast.Load):
            raise UnsafeExpressionError("names are read-only")
        if node.id.startswith("__") or node.id.endswith("__"):
            raise UnsafeExpressionError(f"dunder name not allowed: {node.id!r}")
        if node.id not in allowed_names:
            raise UnsafeExpressionError(f"name not in allowlist: {node.id!r}")
        return
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool) or not isinstance(node.value, (int, float)):
            raise UnsafeExpressionError("only finite numeric literals are allowed")
        try:
            as_float = float(node.value)
        except (OverflowError, ValueError) as exc:
            # e.g. a ~400-digit integer literal — fail closed at compile, never crash the run.
            raise UnsafeExpressionError("numeric literal is out of range") from exc
        if not math.isfinite(as_float):
            raise UnsafeExpressionError("non-finite numeric literal is not allowed")
        if abs(as_float) > MAX_EXPR_LITERAL:
            raise UnsafeExpressionError(
                f"numeric literal magnitude exceeds {MAX_EXPR_LITERAL:g}"
            )
        return
    raise UnsafeExpressionError(f"disallowed expression element: {type(node).__name__}")


def _eval_node(node: ast.AST, env: Mapping[str, float]) -> float | bool | None:
    """Evaluate a pre-vetted node. Only allowlisted node types reach here (validated at compile)."""
    if isinstance(node, ast.BoolOp):
        # Strict (no short-circuit): any undefined operand makes the whole clause undecidable.
        results = [_eval_node(value, env) for value in node.values]
        if any(result is None for result in results):
            return None
        if isinstance(node.op, ast.And):
            return all(_truthy(result) for result in results)
        # Or
        return any(_truthy(result) for result in results)
    if isinstance(node, ast.UnaryOp):
        operand = _eval_node(node.operand, env)
        if operand is None:
            return None
        if isinstance(node.op, ast.Not):
            return not _truthy(operand)
        if isinstance(node.op, ast.USub):
            return _finite_or_none(-_as_number(operand))
        return _finite_or_none(+_as_number(operand))  # UAdd
    if isinstance(node, ast.BinOp):
        left = _eval_node(node.left, env)
        right = _eval_node(node.right, env)
        if left is None or right is None:
            return None
        return _finite_or_none(_binop(node.op, _as_number(left), _as_number(right)))
    if isinstance(node, ast.Compare):
        # MED-A: evaluate EVERY operand first and fail closed if any is undecidable, BEFORE any
        # pairwise comparison. Otherwise a false first pair could short-circuit past an undefined
        # later operand (e.g. ``value > threshold < rate`` with ``rate`` absent) and still yield a
        # bool, letting a detector fire on undefined input.
        raw_operands = [_eval_node(node.left, env)]
        raw_operands.extend(_eval_node(comparator, env) for comparator in node.comparators)
        values: list[float] = []
        for operand in raw_operands:
            if operand is None:
                return None
            values.append(_as_number(operand))
        for op, left_val, right_val in zip(node.ops, values[:-1], values[1:], strict=True):
            if not _compare(op, left_val, right_val):
                return False
        return True
    if isinstance(node, ast.Name):
        if node.id not in env:
            return None
        bound = env[node.id]
        # A name bound to a non-finite value makes the expression undecidable (fail-closed).
        if isinstance(bound, bool) or not isinstance(bound, (int, float)):
            return None
        if not math.isfinite(float(bound)):
            return None
        return float(bound)
    if isinstance(node, ast.Constant):
        value = node.value
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            # Unreachable after _validate; fail closed defensively rather than coerce.
            raise UnsafeExpressionError("non-numeric literal reached evaluation")
        return float(value)
    # Unreachable: _validate rejected everything else at compile time. Fail closed defensively.
    raise UnsafeExpressionError(f"disallowed expression element at eval: {type(node).__name__}")


def _truthy(value: float | bool | None) -> bool:
    return bool(value) if value is not None else False


def _finite_or_none(value: float) -> float | None:
    """Return ``value`` only if finite; a non-finite arithmetic result (overflow to ``inf``) makes
    the expression undecidable so it never fabricates a comparison — fail-closed."""
    return value if math.isfinite(value) else None


def _as_number(value: float | bool) -> float:
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    return float(value)


def _binop(op: ast.operator, left: float, right: float) -> float:
    if isinstance(op, ast.Add):
        return left + right
    if isinstance(op, ast.Sub):
        return left - right
    if isinstance(op, ast.Mult):
        return left * right
    # Div — ZeroDivisionError is caught by SafeExpression.evaluate (fail-closed).
    return left / right


def _compare(op: ast.cmpop, left: float, right: float) -> bool:
    if isinstance(op, ast.Lt):
        return left < right
    if isinstance(op, ast.LtE):
        return left <= right
    if isinstance(op, ast.Gt):
        return left > right
    if isinstance(op, ast.GtE):
        return left >= right
    if isinstance(op, ast.Eq):
        return left == right
    return left != right  # NotEq


__all__ = [
    "MAX_EXPR_DEPTH",
    "MAX_EXPR_LEN",
    "MAX_EXPR_LITERAL",
    "MAX_EXPR_NODES",
    "TELEMETRY_EXPR_NAMES",
    "SafeExpression",
    "UnsafeExpressionError",
    "compile_expression",
    "validate_expression",
]
