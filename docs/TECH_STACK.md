# Faraday Gate — Tech Stack

## Runtime

| Item | Value |
|---|---|
| Language | Python |
| Minimum version | `>=3.10` (`requires-python`) |
| Dev container | 3.13 |
| Packaging | `setuptools>=68`, `setuptools.build_meta` |
| Install | `pip install -e .` (editable) |
| Entry point | `faraday = faraday.cli:app` |

## Core dependencies

These are required and installed by default.

| Package | Constraint | Used for |
|---|---|---|
| `typer` | `>=0.9` | CLI command routing |
| `rich` | `>=13.7` | Tables, panels, colored labels |
| `pyyaml` | `>=6.0` | Policy and config serialization |
| `pydantic` | `>=2.0` | Policy schema validation |

Optional dependency groups are declared in `pyproject.toml` but are not
required to run the MVP:

| Group | Packages | Purpose |
|---|---|---|
| `dev` | `pytest>=8.0`, `ruff>=0.4`, `mypy>=1.10` | Tests and static checks |
| `tui` | `textual>=0.50` | Future interactive dashboard |
| `ast` | `tree-sitter>=0.21`, `tree-sitter-languages>=1.10` | Future AST redaction |
| `ai` | `onnxruntime>=1.17` | Future local inference |

`faraday doctor` reports which optional packages are present and explicitly
reports NPU status as `not verified in MVP`.

## Built-in libraries

No extra dependency is needed for these:

| Capability | Standard library |
|---|---|
| Audit hashing | `hashlib` (SHA-256) |
| Entropy hints | `math.log2` (Shannon entropy) |
| Session metadata | `sqlite3` |
| Audit log format | JSONL via `json` |
| Process wrapping | `subprocess` |
| Path matching | `pathlib`, `fnmatch` |

## Storage layout

```text
.faraday/
├── config.yaml          # active policy
├── policies/default.yaml
├── audit/events.jsonl   # append-only hash chain
├── cache/
└── reports/
```

`.faraday/` is created in the current working directory by `faraday init`.

## Testing

| Item | Value |
|---|---|
| Framework | `pytest` |
| Collection | scoped to `tests/` via `[tool.pytest.ini_options] testpaths` |
| Scope note | `samples/repo` has its own `tests/` package that would otherwise collide |
| Command | `pytest -q` |

## Deliberate exclusions

| Not used | Why |
|---|---|
| Cloud APIs | The product's entire premise is that context must not leave the device |
| LLM SDKs in the core path | Deterministic detection must work with no model present |
| Network calls at all | Zero-egress claim; the MVP makes no external requests |
| Heavy NLP/NER models | Deferred to Phase 2/3 behind the backend abstraction |

## Hardware target

Snapdragon-powered HP AI PCs. The MVP runs on CPU and benchmarks only
deterministic scanners. NPU acceleration is a roadmap item and is not claimed
unless measured on target hardware.
