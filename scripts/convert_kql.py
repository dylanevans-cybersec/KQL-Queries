"""
convert_kql.py

Scans a source GitHub repo for new or changed .kql detection files,
uses a locally hosted LLM via LM Studio to convert each one into a
structured Markdown format, then commits and pushes the resulting
.md files to a destination repo.

Required environment variables:
  LM_STUDIO_URL       - Base URL of LM Studio API (default: http://127.0.0.1:1234/v1)
  LM_STUDIO_MODEL     - Model name as shown in LM Studio (default: mistral-3-3b)
  SOURCE_DIR          - Path to the folder containing .kql files
  DEST_DIR            - Path to the destination folder for .md files
  GIT_AUTHOR_NAME     - Git commit author name
  GIT_AUTHOR_EMAIL    - Git commit author email

Usage:
  python convert_kql.py
"""

import os
import sys
import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path

from openai import OpenAI
import git

# UTF-8 safe logging for Windows
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(open(sys.stdout.fileno(), mode='w', encoding='utf-8', closefd=False))],
)
log = logging.getLogger(__name__)

# Config
LM_STUDIO_URL   = os.environ.get("LM_STUDIO_URL",   "http://127.0.0.1:1234/v1")
LM_STUDIO_MODEL = os.environ.get("LM_STUDIO_MODEL", "mistral-3-3b")
SOURCE_DIR      = Path(os.environ.get("SOURCE_DIR", "source-repo"))
DEST_DIR        = Path(os.environ.get("DEST_DIR",   "dest-repo/content/detections"))
GIT_AUTHOR_NAME = os.environ.get("GIT_AUTHOR_NAME",  "KQL Bot")
GIT_AUTHOR_EMAIL= os.environ.get("GIT_AUTHOR_EMAIL", "kql-bot@noreply.github.com")

STATE_FILE = Path("dest-repo/.kql_conversion_state.json")

client = OpenAI(
    base_url=LM_STUDIO_URL,
    api_key="lm-studio",
)

SYSTEM_PROMPT = """
You are a cybersecurity detection engineering documentation expert. Your job is to convert raw KQL (Kusto Query Language)
detection files into polished, structured Markdown documentation using the given schema.

You must ALWAYS output ONLY valid Markdown - no explanation, no preamble, no code fences
around the entire response. Start your response directly with the YAML front matter block.

Use EXACTLY this structure:

---
title: "<Descriptive title derived from the detection logic>"
date: "<today's date in YYYY-MM-DD format>"
summary: "<1-2 sentence plain-English summary of what the detection catches>"
platform: "<infer the SIEM platform from the query syntax, e.g. Microsoft, Splunk, Elastic>"
tags: ["<tag1>", "<tag2>", "<tag3>"]
author: "<infer from comments in the query, default = Dylan Evans>"
mitre: "<relevant technique ID and name if detectable, otherwise omit this field>"
---

# <Same descriptive title as above>

## Overview

<Short, straight-to-the-point 2-3 sentence explanation of the threat this detection addresses and why it matters.>

## Query

```kql
<the ORIGINAL KQL query, DO NOT CHANGE IT>
```

## Logic Explanation

<In short, simple terms, explain what the query does - what, why and how it filters, aggregates, thresholds, and surfaces.>

## Tuning Notes

<1-2 sentence explanation of potential false positives before each tuning suggestion.>

- <Tuning suggestion 1>
- <Tuning suggestion 2>
- <Tuning suggestion 3>

## References

- <Any relevant references>

Rules:
- Infer as much as possible from the query itself (table names, operators, thresholds).
- Tags should be lowercase, hyphenated, and relevant to the detection (e.g. "lateral-movement", "authentication", "kerberos").
- Do NOT invent details that cannot be inferred from the query.
- Output ONLY the Markdown. No surrounding prose.
- DO NOT SEPARATE KQL BLOCKS - blank lines inside a KQL code block will break rendering.
""".strip()


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {}


def save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))


def find_kql_files(source_dir: Path) -> list[Path]:
    return sorted(source_dir.rglob("*.kql"))


def convert_with_lm_studio(kql_content: str, filename: str) -> str:
    user_message = (
        f"Convert the following KQL detection file to Markdown.\n"
        f"Filename hint: {filename}\n\n"
        f"```kql\n{kql_content}\n```"
    )

    response = client.chat.completions.create(
        model=LM_STUDIO_MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_message},
        ],
        temperature=0.2,
        max_tokens=4096,
    )

    return response.choices[0].message.content.strip()


def write_markdown(dest_dir: Path, kql_path: Path, markdown: str) -> Path:
    relative = kql_path.relative_to(SOURCE_DIR)
    md_path  = dest_dir / relative.with_suffix(".md")
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(markdown, encoding="utf-8")
    log.info(f"  Written to: {md_path}")
    return md_path


def commit_and_push(dest_repo_path: Path, changed_files: list[Path]) -> None:
    repo = git.Repo(dest_repo_path)

    with repo.config_writer() as cfg:
        cfg.set_value("user", "name",  GIT_AUTHOR_NAME)
        cfg.set_value("user", "email", GIT_AUTHOR_EMAIL)

    all_files = [str(f.relative_to(dest_repo_path)) for f in changed_files]
    all_files.append(str(STATE_FILE.relative_to(dest_repo_path)))

    repo.index.add(all_files)

    if not repo.index.diff("HEAD"):
        log.info("Nothing to commit - all files already up to date.")
        return

    today   = datetime.utcnow().strftime("%Y-%m-%d")
    count   = len(changed_files)
    message = f"chore: convert {count} KQL detection(s) to Markdown [{today}]"

    repo.index.commit(message)
    origin = repo.remote(name="origin")
    origin.push()
    log.info(f"Pushed {count} file(s) with message: '{message}'")


def main() -> None:
    log.info("=" * 60)
    log.info("KQL -> Markdown Conversion Pipeline (LM Studio)")
    log.info(f"  Model  : {LM_STUDIO_MODEL}")
    log.info(f"  API    : {LM_STUDIO_URL}")
    log.info(f"  Source : {SOURCE_DIR}")
    log.info(f"  Dest   : {DEST_DIR}")
    log.info("=" * 60)

    try:
        models = client.models.list()
        available = [m.id for m in models.data]
        log.info(f"LM Studio reachable. Available models: {available}")
        if LM_STUDIO_MODEL not in available:
            log.warning(
                f"Model '{LM_STUDIO_MODEL}' not found in LM Studio. "
                f"Make sure it is loaded. Available: {available}"
            )
    except Exception as exc:
        log.error(f"Cannot reach LM Studio at {LM_STUDIO_URL}: {exc}")
        log.error("Make sure LM Studio is running and the server is enabled.")
        sys.exit(1)

    if not SOURCE_DIR.exists():
        log.error(f"Source directory not found: {SOURCE_DIR}")
        sys.exit(1)

    kql_files = find_kql_files(SOURCE_DIR)
    log.info(f"Found {len(kql_files)} .kql file(s) in source repo.")

    if not kql_files:
        log.info("Nothing to do. Exiting.")
        return

    state     = load_state()
    converted = []
    skipped   = 0
    errors    = 0

    for kql_path in kql_files:
        key          = str(kql_path.relative_to(SOURCE_DIR))
        current_hash = file_hash(kql_path)

        if state.get(key) == current_hash:
            log.info(f"[SKIP] {key}  (unchanged)")
            skipped += 1
            continue

        log.info(f"[CONVERT] {key}")
        try:
            kql_content = kql_path.read_text(encoding="utf-8")
            markdown    = convert_with_lm_studio(kql_content, kql_path.name)
            md_path     = write_markdown(DEST_DIR, kql_path, markdown)
            converted.append(md_path)
            state[key]  = current_hash

        except Exception as exc:
            log.error(f"  ERROR converting {key}: {exc}")
            errors += 1

    log.info("-" * 60)
    log.info(f"Converted : {len(converted)}")
    log.info(f"Skipped   : {skipped}")
    log.info(f"Errors    : {errors}")

    if converted:
        save_state(state)
        dest_repo_root = Path("dest-repo")
        commit_and_push(dest_repo_root, converted)
    else:
        log.info("No new conversions - skipping git push.")

    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()