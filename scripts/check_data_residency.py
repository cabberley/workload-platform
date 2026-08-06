#!/usr/bin/env python
"""Static data-residency assertion for the Workloads Platform (HITRUST CSF: Data Protection).

Data residency is honored **by construction** when every deployable Azure resource lands in a
SINGLE region — the customer's resource-group region — rather than any hard-coded, foreign, or
deploy-time-overridable region. This check statically reads ``infra/bicep`` (READ-ONLY; it never
modifies a bicep file) and **fails closed** (non-zero exit) whenever it cannot *prove* a
``location``
resolves to the single resource-group region.

**Residency boundary assumption.** The only accepted *dynamic* location source is
``resourceGroup().location`` — every resource inherits the region the customer chose for the
resource
group. A location may also be a literal on the explicit **permitted-regions** allow-list (empty by
default, i.e. strict ``resourceGroup().location``-only). Everything else fails closed.

It resolves indirection before deciding, so it cannot be fooled by:

* **variable / param indirection** — ``var location = 'eastus'`` then ``location: location`` is
  resolved to the literal and rejected; a ``param`` is accepted **only** if its default resolves to
  a
  permitted region (or ``resourceGroup().location``). A **defaultless** parameter is *not* trusted —
  its value is deploy-time-controlled — unless every ``module`` call site that binds it is validated
  (see below);
* **object spreads / composed objects** — a foreign ``location:`` inside ``{ ...base, location: 'x'
  }`` (or inside the spread source object) is matched **inline**, not only at line start;
* **module call-site bindings** — a child module's defaultless ``location`` param is trusted only
  when *every* parent ``module ... = { params: { location: <expr> } }`` binding resolves to a
  permitted value; a foreign or unresolved binding at any call site is a violation;
* **unresolved / dynamic values** — anything not provably a permitted region (unknown identifier,
  composed object, computed expression, defaultless param with no validated binding, param whose
  default is foreign) is a **VIOLATION**, never passed vacuously.

Design notes:
  * **stdlib only** (``re``) and line-oriented — no bicep toolchain or Azure creds required, fast in
    CI. (Parsing ``az bicep build`` output would also work offline, but a resolved line scan keeps
    the check dependency-light and unit-testable on synthetic snippets.)
  * ``scan_bicep_text(text, filename, *, permitted_regions, permitted_params)`` is the per-file
    core;
    ``run_check`` first computes each child module's validated ``permitted_params`` from the whole
    tree's module bindings, then scans every file with that context.

Usage::

    python scripts/check_data_residency.py                 # scan infra/bicep (default)
    python scripts/check_data_residency.py --infra infra/bicep

Exit codes: ``0`` single-region by construction · ``1`` a residency violation was found · ``2`` an
internal/usage error (e.g. the infra directory is missing — fail closed rather than pass vacuously).
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]

# The only *directly* permitted dynamic location expression. Everything else must resolve to this or
# to a literal on the permitted-regions allow-list.
_PERMITTED_DIRECT: frozenset[str] = frozenset({"resourceGroup().location"})

# Region literals explicitly accepted as the single permitted region. Empty by default: strict
# resourceGroup().location-only. (Override per call site / test to pin a designated region.)
_PERMITTED_REGIONS: frozenset[str] = frozenset()

# A representative set of Azure region slugs. A resolved literal is a hard-coded *region* if its
# normalized form appears here (and is not permitted); any other literal is a hard-coded location.
_AZURE_REGIONS: frozenset[str] = frozenset(
    {
        "eastus", "eastus2", "eastus3", "westus", "westus2", "westus3", "centralus",
        "northcentralus", "southcentralus", "westcentralus",
        "canadacentral", "canadaeast", "brazilsouth",
        "northeurope", "westeurope", "uksouth", "ukwest", "francecentral", "francesouth",
        "germanywestcentral", "germanynorth", "switzerlandnorth", "switzerlandwest",
        "norwayeast", "norwaywest", "swedencentral", "polandcentral", "italynorth", "spaincentral",
        "eastasia", "southeastasia", "japaneast", "japanwest", "koreacentral", "koreasouth",
        "australiaeast", "australiasoutheast", "australiacentral", "australiacentral2",
        "centralindia", "southindia", "westindia", "jioindiawest",
        "uaenorth", "uaecentral", "qatarcentral", "southafricanorth", "southafricawest",
        "israelcentral",
    }
)

# Inline-aware AND tolerant of formatting: a ``location`` key anywhere on a line (object literals /
# spreads / module params), with optional surrounding quotes, any case, and optional whitespace
# around the colon — so ``location :``, ``'Location':`` and ``LOCATION:`` cannot slip past. The
# negative lookbehind avoids matching ``mylocation:`` / ``x.location:`` (e.g. ``allocation:``).
_LOCATION_PROPERTY_RE = re.compile(
    r"""(?<![\w.])['"]?location['"]?\s*:\s*(?P<rhs>'[^']*'|[^,}\n]+)""",
    re.IGNORECASE,
)
_PARAM_DECL_RE = re.compile(r"^\s*param\s+(?P<name>\w+)\s+\w+\s*(?:=\s*(?P<default>.+?)\s*)?$")
_VAR_DECL_RE = re.compile(r"^\s*var\s+(?P<name>\w+)\s*=\s*(?P<value>.*?)\s*$")
_MODULE_START_RE = re.compile(r"^\s*module\s+\w+\s+'(?P<path>[^']+)'\s*=")
_BINDING_RE = re.compile(r"^\s*(?P<key>[A-Za-z_]\w*):\s*(?P<val>.+?)\s*$")
_QUOTED_RE = re.compile(r"^'(?P<value>[^']*)'$")
_IDENT_RE = re.compile(r"^[A-Za-z_]\w*$")

_MAX_RESOLVE_DEPTH = 8


@dataclass(frozen=True)
class Violation:
    """One data-residency failure, with the source location that tripped it."""

    filename: str
    line: int
    kind: str
    detail: str


def _strip_comment(rhs: str) -> str:
    """Drop a trailing ``//`` line comment (bicep) and surrounding whitespace."""
    idx = rhs.find("//")
    if idx != -1:
        rhs = rhs[:idx]
    return rhs.strip()


def _strip_comments(text: str) -> str:
    """Remove ``/* */`` block and ``//`` line comments, preserving newlines (and line numbers).

    Comment characters are replaced with spaces (newlines kept) so the offset→line mapping is
    unchanged. Single-quoted string literals are preserved verbatim so a ``//`` or ``/*`` inside a
    string value (e.g. a URL) is never mistaken for a comment. This lets the multiline ``location``
    scan see through ``location /* gap */ : 'x'`` and ``location:``-on-its-own-line layouts.
    """
    out: list[str] = []
    i, n = 0, len(text)
    in_block = in_line = in_str = False
    while i < n:
        ch = text[i]
        two = text[i : i + 2]
        if in_block:
            out.append("\n" if ch == "\n" else " ")
            if two == "*/":
                in_block = False
                out.append(" ")
                i += 2
                continue
            i += 1
            continue
        if in_line:
            if ch == "\n":
                in_line = False
                out.append("\n")
            else:
                out.append(" ")
            i += 1
            continue
        if in_str:
            out.append(ch)
            if ch == "'":
                in_str = False
            i += 1
            continue
        if ch == "'":
            in_str = True
            out.append(ch)
            i += 1
            continue
        if two == "/*":
            in_block = True
            out.append("  ")
            i += 2
            continue
        if two == "//":
            in_line = True
            out.append("  ")
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _normalize_region(value: str) -> str:
    return "".join(ch for ch in value.lower() if ch.isalnum())


def _build_symbol_table(text: str) -> dict[str, tuple[str, str | None]]:
    """Map each declared name to ``(kind, rhs)`` where kind is ``"var"`` or ``"param"``.

    For a ``param`` the rhs is its default (or ``None`` if it has none); for a ``var`` the rhs is
    the
    (single-line) value, or ``None`` when the value opens a multi-line/complex literal we treat as
    unresolvable. Deliberately conservative, fail-closed model of bicep scoping.
    """
    table: dict[str, tuple[str, str | None]] = {}
    for raw in text.splitlines():
        line = _strip_comment(raw)
        param = _PARAM_DECL_RE.match(line)
        if param is not None:
            default = param.group("default")
            table[param.group("name")] = ("param", default if default else None)
            continue
        var = _VAR_DECL_RE.match(line)
        if var is not None:
            value = var.group("value")
            if not value or value.startswith("{") or value.startswith("["):
                table[var.group("name")] = ("var", None)
            else:
                table[var.group("name")] = ("var", value)
    return table


def _resolve(
    token: str,
    symbols: dict[str, tuple[str, str | None]],
    permitted_params: frozenset[str],
    depth: int = 0,
) -> tuple[str, str | None]:
    """Resolve a ``location`` RHS to ``("permitted", None)``, ``("literal", value)`` or
    ``("unresolved", None)``. Fail-closed: anything not provably permitted stays unresolved.

    A defaultless ``param`` is permitted **only** when its name is in ``permitted_params`` (i.e. the
    caller has validated every module call-site binding for it); otherwise it is unresolved.
    """
    token = _strip_comment(token)
    if depth > _MAX_RESOLVE_DEPTH:
        return ("unresolved", None)
    if token in _PERMITTED_DIRECT:
        return ("permitted", None)
    quoted = _QUOTED_RE.match(token)
    if quoted is not None:
        return ("literal", quoted.group("value"))
    if _IDENT_RE.match(token):
        entry = symbols.get(token)
        if entry is None:
            return ("unresolved", None)
        kind, rhs = entry
        if kind == "param":
            if rhs is None:
                return ("permitted", None) if token in permitted_params else ("unresolved", None)
            return _resolve(rhs, symbols, permitted_params, depth + 1)
        if rhs is None:
            return ("unresolved", None)
        return _resolve(rhs, symbols, permitted_params, depth + 1)
    return ("unresolved", None)


def _classify_location(
    status: str,
    value: str | None,
    permitted_regions: frozenset[str],
    filename: str,
    lineno: int,
    *,
    context: str,
) -> Violation | None:
    """Turn a resolved location outcome into a violation (or ``None`` if it is permitted)."""
    if status == "permitted":
        return None
    if status == "literal" and value is not None:
        if _normalize_region(value) in permitted_regions:
            return None
        if _normalize_region(value) in _AZURE_REGIONS:
            return Violation(
                filename, lineno, "hardcoded-region",
                f"{context} resolves to hard-coded region {value!r} — resources must use the "
                "single "
                "location parameter so data residency stays single-region",
            )
        return Violation(
            filename, lineno, "hardcoded-location",
            f"{context} resolves to a hard-coded literal {value!r} rather than the single location "
            "parameter / resourceGroup().location",
        )
    return Violation(
        filename, lineno, "unresolved-location",
        f"{context} cannot be proven to resolve to the single resource-group region "
        "(resourceGroup().location) — failing closed rather than assuming it is safe",
    )


def scan_bicep_text(
    text: str,
    filename: str,
    *,
    permitted_regions: frozenset[str] = _PERMITTED_REGIONS,
    permitted_params: frozenset[str] = frozenset(),
) -> list[Violation]:
    """Return every data-residency violation in one bicep file's ``text`` (empty == clean).

    Offline fallback (when ``az`` / compiled ARM is unavailable): comments are stripped first
    (``/* */`` and ``//``, newlines preserved) and the ``location`` property is matched over the
    WHOLE text so multiline (``location:`` then the value on the next line) and comment-interrupted
    (``location /* gap */ :``) layouts cannot slip past. Line numbers stay accurate because the
    comment stripper preserves every newline.
    """
    violations: list[Violation] = []
    clean = _strip_comments(text)
    symbols = _build_symbol_table(clean)

    # Validate the location param's default directly (foreign/unresolved default is a leak).
    for lineno, line in enumerate(clean.splitlines(), start=1):
        param = _PARAM_DECL_RE.match(line)
        if param is not None and param.group("name") == "location":
            default = param.group("default")
            if default is not None:
                status, value = _resolve(default, symbols, permitted_params)
                v = _classify_location(
                    status, value, permitted_regions, filename, lineno,
                    context="param location default",
                )
                if v is not None:
                    # A foreign default is best labelled 'param-default'.
                    kind = "param-default" if v.kind == "hardcoded-region" else v.kind
                    violations.append(Violation(filename, lineno, kind, v.detail))

    # Match ``location`` properties anywhere (multiline-aware) on the comment-stripped text.
    for match in _LOCATION_PROPERTY_RE.finditer(clean):
        rhs = match.group("rhs").strip()
        status, value = _resolve(rhs, symbols, permitted_params)
        lineno = clean.count("\n", 0, match.start()) + 1
        v = _classify_location(
            status, value, permitted_regions, filename, lineno,
            context=f"location {rhs!r}",
        )
        if v is not None:
            violations.append(v)
    return violations


def _binding_is_permitted(
    status: str, value: str | None, permitted_regions: frozenset[str]
) -> bool:
    """True iff a module call-site ``location`` binding resolves to a permitted value."""
    if status == "permitted":
        return True
    if status == "literal" and value is not None:
        return _normalize_region(value) in permitted_regions
    return False


def _module_location_bindings(
    text: str,
    symbols: dict[str, tuple[str, str | None]],
    parent_path: Path,
) -> list[tuple[Path, str, tuple[str, str | None]]]:
    """Collect ``(child_abs_path, param_key, resolution)`` for every module param binding.

    Bindings are resolved against the *parent* file's symbols with no trusted defaultless params
    (conservative / fail-closed for deep chains, which this tree does not use).
    """
    results: list[tuple[Path, str, tuple[str, str | None]]] = []
    lines = text.splitlines()
    i, n = 0, len(lines)
    while i < n:
        start = _MODULE_START_RE.match(_strip_comment(lines[i]))
        if start is None:
            i += 1
            continue
        child_abs = (parent_path.parent / start.group("path")).resolve()
        depth = 0
        started = False
        j = i
        while j < n:
            line = _strip_comment(lines[j])
            if j > i:
                binding = _BINDING_RE.match(line)
                if binding is not None:
                    resolution = _resolve(binding.group("val"), symbols, frozenset())
                    results.append((child_abs, binding.group("key"), resolution))
            depth += line.count("{") + line.count("[")
            depth -= line.count("}") + line.count("]")
            if started and depth <= 0:
                break
            if depth > 0:
                started = True
            j += 1
        i = j + 1
    return results


def _compute_permitted_params(
    files: list[tuple[Path, str, str, dict[str, tuple[str, str | None]]]],
    permitted_regions: frozenset[str],
) -> dict[Path, frozenset[str]]:
    """For each child module file, the param keys whose *every* call-site binding is permitted."""
    bindings: dict[Path, dict[str, list[bool]]] = {}
    for abs_path, _display, text, symbols in files:
        for child_abs, key, resolution in _module_location_bindings(text, symbols, abs_path):
            status, value = resolution
            ok = _binding_is_permitted(status, value, permitted_regions)
            bindings.setdefault(child_abs, {}).setdefault(key, []).append(ok)
    result: dict[Path, frozenset[str]] = {}
    for child_abs, keymap in bindings.items():
        permitted = {key for key, oks in keymap.items() if oks and all(oks)}
        if permitted:
            result[child_abs] = frozenset(permitted)
    return result


def scan_bicep_file(
    path: Path,
    *,
    display: str | None = None,
    permitted_regions: frozenset[str] = _PERMITTED_REGIONS,
    permitted_params: frozenset[str] = frozenset(),
) -> list[Violation]:
    """Scan one ``.bicep`` file on disk (read-only)."""
    name = display if display is not None else path.name
    return scan_bicep_text(
        path.read_text(encoding="utf-8"),
        name,
        permitted_regions=permitted_regions,
        permitted_params=permitted_params,
    )


# --------------------------------------------------------------------------------------
# Structural verification via compiled ARM (preferred): robust to whitespace/quoting/case and
# resolves vars/params/module bindings through the bicep compiler. Runs OFFLINE (no Azure creds).
# --------------------------------------------------------------------------------------
def _az_executable() -> str | None:
    """Locate the ``az`` CLI (``az.cmd`` on Windows, ``az`` on the Linux CI runner)."""
    return shutil.which("az")


def compile_bicep_to_arm(path: Path) -> dict | None:
    """Compile a bicep file to ARM JSON via ``az bicep build`` (offline). ``None`` on any failure.

    A ``None`` result is NOT a silent pass: ``run_check`` still applies the static text scan to
    every file, so a compile failure just falls back to that fail-closed scan.
    """
    az = _az_executable()
    if az is None:
        return None
    try:
        proc = subprocess.run(  # noqa: S603 — fixed argv, no shell, offline build.
            [az, "bicep", "build", "--file", str(path), "--stdout"],
            capture_output=True,
            text=True,
            timeout=180,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    try:
        loaded = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    return loaded if isinstance(loaded, dict) else None


def _resolve_arm_expr(
    expr: object,
    params: dict[str, tuple[str, str | None]],
    variables: dict[str, object],
    depth: int = 0,
) -> tuple[str, str | None]:
    """Resolve a compiled-ARM ``location`` expression to permitted / literal / unresolved."""
    if not isinstance(expr, str):
        return ("unresolved", None)
    text = expr.strip()
    if not (text.startswith("[") and text.endswith("]")):
        return ("literal", text)
    if text.startswith("[["):  # ARM-escaped literal ("[[x]" is the literal "[x]")
        return ("literal", text[1:])
    if depth > _MAX_RESOLVE_DEPTH:
        return ("unresolved", None)
    inner = text[1:-1].strip()
    if re.sub(r"\s+", "", inner) == "resourceGroup().location":
        return ("permitted", None)
    param_match = re.fullmatch(r"parameters\('([^']+)'\)", inner)
    if param_match is not None:
        return params.get(param_match.group(1), ("unresolved", None))
    var_match = re.fullmatch(r"variables\('([^']+)'\)", inner)
    if var_match is not None:
        value = variables.get(var_match.group(1))
        if value is None:
            return ("unresolved", None)
        return _resolve_arm_expr(value, params, variables, depth + 1)
    return ("unresolved", None)


def _resolve_arm_params(
    template: dict, bound: dict[str, tuple[str, str | None]]
) -> tuple[dict[str, tuple[str, str | None]], dict[str, object]]:
    """Resolve a template's parameters from parent bindings + declared defaults."""
    param_defs = template.get("parameters", {}) or {}
    variables = template.get("variables", {}) or {}
    resolved: dict[str, tuple[str, str | None]] = {}
    for name, pdef in param_defs.items():
        if name in bound:
            resolved[name] = bound[name]
        elif isinstance(pdef, dict) and "defaultValue" in pdef:
            resolved[name] = _resolve_arm_expr(pdef["defaultValue"], {}, variables)
        else:
            resolved[name] = ("unresolved", None)
    return resolved, variables


def scan_arm_template(
    template: dict,
    bound: dict[str, tuple[str, str | None]],
    filename: str,
    permitted_regions: frozenset[str],
    violations: list[Violation],
) -> None:
    """Structurally verify every resource ``location`` in a compiled ARM template (recursive)."""
    resolved_params, variables = _resolve_arm_params(template, bound)
    resources = template.get("resources", [])
    if isinstance(resources, dict):
        resources = list(resources.values())
    if not isinstance(resources, list):
        return
    for resource in resources:
        if not isinstance(resource, dict):
            continue
        rtype = resource.get("type", "?")
        location = resource.get("location")
        if location is not None:
            status, value = _resolve_arm_expr(location, resolved_params, variables)
            v = _classify_location(
                status, value, permitted_regions, filename, 0,
                context=f"compiled resource {rtype} location",
            )
            if v is not None:
                violations.append(v)
        if resource.get("type") == "Microsoft.Resources/deployments":
            props = resource.get("properties", {}) or {}
            child_template = props.get("template")
            if isinstance(child_template, dict):
                child_bound: dict[str, tuple[str, str | None]] = {}
                for name, spec in (props.get("parameters") or {}).items():
                    if isinstance(spec, dict) and "value" in spec:
                        child_bound[name] = _resolve_arm_expr(
                            spec["value"], resolved_params, variables
                        )
                scan_arm_template(
                    child_template, child_bound, filename, permitted_regions, violations
                )


def _referenced_module_paths(text: str, parent_path: Path) -> set[Path]:
    """Absolute paths of every module a bicep file references (so entry templates can be found)."""
    referenced: set[Path] = set()
    for raw in text.splitlines():
        start = _MODULE_START_RE.match(_strip_comment(raw))
        if start is not None:
            referenced.add((parent_path.parent / start.group("path")).resolve())
    return referenced


def run_check(
    infra_dir: Path, *, permitted_regions: frozenset[str] = _PERMITTED_REGIONS
) -> list[Violation]:
    """Scan every ``*.bicep`` under ``infra_dir`` (read-only). Raises if the dir is missing/empty.

    Two complementary controls, both fail-closed:

    1. **Static cross-file scan** — resolves ``var``/``param`` indirection, object spreads and
       module call-site bindings over the bicep text (tolerant of whitespace/quoting/case).
    2. **Compiled-ARM structural check** (preferred, when ``az`` is available) — compiles each entry
       template offline and inspects every resolved resource ``location`` in the ARM JSON, which is
       immune to source formatting and resolves vars/params/module params through the compiler.

    A missing/empty infra tree raises (never a vacuous pass).
    """
    if not infra_dir.is_dir():
        raise FileNotFoundError(f"infra directory not found: {infra_dir}")
    paths = sorted(infra_dir.rglob("*.bicep"))
    if not paths:
        raise FileNotFoundError(f"no .bicep files found under {infra_dir}")

    files: list[tuple[Path, str, str, dict[str, tuple[str, str | None]]]] = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        files.append(
            (path.resolve(), str(path.relative_to(infra_dir)), text, _build_symbol_table(text))
        )

    permitted_params_by_file = _compute_permitted_params(files, permitted_regions)

    violations: list[Violation] = []
    for abs_path, display, text, _symbols in files:
        violations.extend(
            scan_bicep_text(
                text,
                display,
                permitted_regions=permitted_regions,
                permitted_params=permitted_params_by_file.get(abs_path, frozenset()),
            )
        )

    # Preferred structural pass: compile the ENTRY templates (those not referenced as a module by
    # another file) so their nested module bindings are resolved by the bicep compiler.
    if _az_executable() is not None:
        referenced: set[Path] = set()
        for abs_path, _display, text, _symbols in files:
            referenced |= _referenced_module_paths(text, abs_path)
        for abs_path, display, _text, _symbols in files:
            if abs_path in referenced:
                continue
            template = compile_bicep_to_arm(abs_path)
            if template is None:
                continue  # static scan above already covered this file (not a silent pass)
            scan_arm_template(template, {}, display, permitted_regions, violations)

    return violations


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="check_data_residency.py",
        description=(
            "Fail closed if any bicep resource is not co-located in the single resource-group "
            "region (data-residency assertion). Read-only over infra/bicep."
        ),
    )
    parser.add_argument(
        "--infra",
        type=Path,
        default=_REPO_ROOT / "infra" / "bicep",
        help="Directory of bicep templates to scan (default: infra/bicep).",
    )
    args = parser.parse_args(argv)

    try:
        violations = run_check(args.infra)
    except (FileNotFoundError, OSError) as exc:
        print(f"ERROR: could not run data-residency check: {exc}", file=sys.stderr)
        return 2

    if violations:
        print(f"FAIL: {len(violations)} data-residency violation(s) found:", file=sys.stderr)
        for v in violations:
            print(f"  {v.filename}:{v.line} [{v.kind}] {v.detail}", file=sys.stderr)
        print(
            "\nEvery deployable resource must use the single location parameter "
            "(resourceGroup().location) so customer data stays in one region.",
            file=sys.stderr,
        )
        return 1

    file_count = len(sorted(args.infra.rglob("*.bicep")))
    print(
        f"OK: data-residency check passed — every resource in {file_count} bicep file(s) is "
        "co-located in the single resource-group region (resourceGroup().location)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
