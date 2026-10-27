"""Bounded recursive discovery of in-scope subdomains using Subfinder."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path


def read_lines(path: Path) -> list[str]:
    if not path.is_file():
        raise FileNotFoundError(path)
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def write_lines(path: Path, values: list[str]) -> None:
    path.write_text("".join(f"{item}\n" for item in dict.fromkeys(values)), encoding="utf-8")


def is_in_scope(host: str, roots: list[str]) -> bool:
    host = host.strip().lower().rstrip(".")
    return any(host == root or host.endswith("." + root) for root in roots)


def recursive_subfinder(
    seed_hosts: list[str],
    roots: list[str],
    out_dir: Path,
    *,
    max_depth: int = 2,
    max_hosts: int = 5000,
    all_sources: bool = False,
) -> list[str]:
    """Discover descendants in waves while enforcing root-domain scope and hard limits.

    Each wave invokes Subfinder only for hosts discovered in the previous wave.
    Results are deduplicated, validated, and capped before the next wave.
    """
    if not 1 <= max_depth <= 5:
        raise ValueError("max_depth must be between 1 and 5")
    if max_hosts < 1:
        raise ValueError("max_hosts must be at least 1")

    normalized_roots = list(dict.fromkeys(r.lower().strip().rstrip(".") for r in roots if r.strip()))
    if not normalized_roots:
        raise ValueError("at least one root domain is required")
    seed_set = {h.lower().strip().rstrip(".") for h in seed_hosts if is_in_scope(h, normalized_roots)}
    frontier = list(sorted(seed_set))
    initial_seed_count = len(seed_set)
    discovered: list[str] = []
    known = set(seed_set)
    audit: list[dict[str, object]] = []
    discovered: list[str] = []
    audit: list[dict[str, object]] = []

    for depth in range(1, max_depth + 1):
        if not frontier or len(discovered) >= max_hosts:
            break
        frontier = frontier[: max(0, max_hosts - len(discovered))]
        input_file = out_dir / f"recursive-subfinder-depth-{depth}-input.txt"
        output_file = out_dir / f"recursive-subfinder-depth-{depth}.txt"
        log_file = out_dir / f"recursive-subfinder-depth-{depth}.log"
        write_lines(input_file, frontier)
        cmd = ["subfinder", "-dL", str(input_file), "-silent", "-o", str(output_file)]
        if all_sources:
            cmd.insert(1, "-all")
        output_file.unlink(missing_ok=True)
        with log_file.open("w", encoding="utf-8", errors="replace") as log:
            log.write("COMMAND: " + " ".join(cmd) + "\n")
            try:
                proc = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, check=False)
            except OSError as exc:
                raise RuntimeError(f"Could not start Subfinder at recursion depth {depth}: {exc}") from exc
        if proc.returncode != 0:
            raise RuntimeError(
                f"Subfinder recursion depth {depth} exited with code {proc.returncode}; inspect {log_file}"
            )

        wave: list[str] = []
        if output_file.is_file():
            for raw in read_lines(output_file):
                host = raw.lower().strip().rstrip(".")
                if (len(host) > 253 or not re.fullmatch(
                    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*",
                    host,
                )):
                    continue
                if host in known or not is_in_scope(host, normalized_roots):
                    continue
                wave.append(host)

        # Deterministic order keeps result files stable between runs.
        wave = sorted(set(wave))[: max(0, max_hosts - len(discovered))]
        known.update(wave)
        discovered.extend(wave)
        frontier = wave
        audit.append({"depth": depth, "input_hosts": len(read_lines(input_file)),
                      "new_hosts": len(wave), "return_code": proc.returncode})
        print(f"[+] Recursive Subfinder depth {depth}: {len(wave)} new in-scope subdomain(s)")

    write_lines(out_dir / "recursive-subdomains.txt", discovered)
    import json
    (out_dir / "recursive-subdomains.json").write_text(
        json.dumps({"max_depth": max_depth, "max_hosts": max_hosts,
                    "seed_hosts": initial_seed_count, "roots": normalized_roots, "count": len(discovered), "waves": audit,
                    "results": discovered}, indent=2),
        encoding="utf-8",
    )
    return discovered
