#!/usr/bin/env python3
"""Render README terminal screenshots from a captured --dry-run transcript.

Answers piped into a --plain session are not echoed, so every prompt runs
into the next line of output. Pass the same answers with --answers and they
are written back after their prompts, the way an operator would see them.

    printf '%s\\n' n n ExampleRelay ... > answers.txt
    ./setup-tor-guard-relay.sh --dry-run --plain < answers.txt > transcript.txt
    scripts/render-readme-screenshots.py transcript.txt --answers answers.txt
"""

from __future__ import annotations

import argparse
import html
import re
from pathlib import Path

# A prompt ends in ": " and is followed by the next step prefix or end of line.
PROMPT = re.compile(r": (?=\[\d\d\] |$)")
FONT = "ui-monospace, 'DejaVu Sans Mono', Consolas, monospace"
WIDTH = 1180
LINE_HEIGHT = 22
MAX_COLUMNS = 128


Row = tuple[str, "str | None"]


def restore_answers(lines: list[str], answers: list[str]) -> list[Row]:
    """Split prompt lines into (text, typed answer) rows; answer is None for output."""
    pending = list(answers)
    result: list[Row] = []
    for line in lines:
        while pending:
            match = PROMPT.search(line)
            if not match:
                break
            answer = pending.pop(0)
            result.append((line[: match.end()], answer))
            line = line[match.end() :]
            if not line:
                break
        else:
            result.append((line, None))
            continue
        if line:
            result.append((line, None))
    return result


def color_for(line: str) -> str:
    if "[OK]" in line:
        return "#50fa7b"
    if "[WARN]" in line:
        return "#f1fa8c"
    if "[ERROR]" in line:
        return "#ff6e6e"
    if "+--" in line or line.startswith("Tor Relay Setup"):
        return "#23d6c8"
    return "#d8edf3"


def render_svg(path: Path, title: str, rows: list[Row]) -> None:
    top = 64
    height = top + LINE_HEIGHT * len(rows) + 30
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{height}" '
        f'viewBox="0 0 {WIDTH} {height}" role="img" aria-label="{html.escape(title)}">',
        f"<title>{html.escape(title)}</title>",
        '<rect width="100%" height="100%" rx="14" fill="#071923"/>',
        '<rect width="100%" height="42" rx="14" fill="#0d2b38"/>',
        '<circle cx="26" cy="21" r="7" fill="#ff5f57"/>'
        '<circle cx="50" cy="21" r="7" fill="#ffbd2e"/>'
        '<circle cx="74" cy="21" r="7" fill="#28c840"/>',
        f'<text x="104" y="27" font-family="{FONT}" font-size="15" fill="#a8d8e8">'
        f"{html.escape(title)}</text>",
    ]
    y = top
    for text, answer in rows:
        text = text[:MAX_COLUMNS]
        typed = ""
        if answer is not None:
            shown = answer or "⏎"
            typed = f'<tspan fill="#ffb86c" font-weight="bold">{html.escape(shown)}</tspan>'
        out.append(
            f'<text x="28" y="{y}" font-family="{FONT}" font-size="15" '
            f'fill="{color_for(text)}" xml:space="preserve">{html.escape(text)}{typed}</text>'
        )
        y += LINE_HEIGHT
    out.append("</svg>")
    path.write_text("\n".join(out) + "\n", encoding="utf-8")


def section(rows: list[Row], start: str, stop: str | None) -> list[Row]:
    begin = next((i for i, (text, _) in enumerate(rows) if start in text), 0)
    end = len(rows)
    if stop:
        end = next((i for i, (text, _) in enumerate(rows) if stop in text and i > begin), end)
    return rows[begin:end]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("transcript", type=Path)
    parser.add_argument("--answers", type=Path, help="answers that were piped into the session")
    parser.add_argument("--out-dir", type=Path, default=Path("docs/assets"))
    parser.add_argument("--label", default="Ubuntu 24.04 dry run")
    args = parser.parse_args()

    lines = args.transcript.read_text(encoding="utf-8", errors="replace").splitlines()
    answers = args.answers.read_text(encoding="utf-8").splitlines() if args.answers else []
    rows = restore_answers(lines, answers) if answers else [(line, None) for line in lines]
    args.out_dir.mkdir(parents=True, exist_ok=True)

    render_svg(
        args.out_dir / "tor-relay-setup-first-run.svg",
        f"{args.label}: guided setup",
        section(rows, "Relay Identity", "Bandwidth and Traffic"),
    )
    render_svg(
        args.out_dir / "tor-relay-setup-review.svg",
        f"{args.label}: final review",
        section(rows, "Review Before Applying", "Planned privileged changes"),
    )


if __name__ == "__main__":
    main()
