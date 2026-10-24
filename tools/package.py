"""Build the submission zip exactly as the graders receive it, and check that it stands alone.

The zip holds the tracked files of submission/ (no model, no llama.cpp runtime, no
caches) plus the scorecard of a chosen run as submission/scorecard.json. With --check,
it unzips into a fresh folder next to a copy of the evaluator and imports the detector
there, so a file that only exists in this repository shows up now, not on the graders'
machine. The corrected answer key goes next to the zip for the rehearsal run.

    python tools/package.py --scorecard results/v1.4-full-mac/scorecard.json --check
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST = os.path.join(ROOT, "dist")


def tracked(folder: str) -> list[str]:
    out = subprocess.run(["git", "ls-files", folder], cwd=ROOT, check=True, capture_output=True, text=True).stdout
    return [p for p in out.splitlines() if p]


ZIP_DATE = (1980, 1, 1, 0, 0, 0)      # every entry gets this date, not the file's modification time


def add(zf: zipfile.ZipFile, src: str, arcname: str) -> None:
    info = zipfile.ZipInfo(arcname, date_time=ZIP_DATE)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    with open(src, "rb") as fh:
        zf.writestr(info, fh.read())


def build(scorecard: str | None) -> str:
    os.makedirs(DIST, exist_ok=True)
    path = os.path.join(DIST, "submission.zip")
    files = tracked("submission")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel in files:
            add(zf, os.path.join(ROOT, rel), rel)
        if scorecard:
            add(zf, scorecard, "submission/scorecard.json")
    answers = os.path.join(ROOT, "data", "cache", "eval_answers.json")
    if os.path.isfile(answers):
        shutil.copy(answers, os.path.join(DIST, "eval_answers.json"))
    print("wrote {} ({} files{}, {:.0f} KB)".format(os.path.relpath(path, ROOT), len(files),
          " + scorecard.json" if scorecard else "", os.path.getsize(path) / 1024))
    return path


def check(path: str) -> None:
    """Unzip next to a copy of the evaluator, as the graders will, and import the detector."""
    with tempfile.TemporaryDirectory() as tmp:
        shutil.copytree(os.path.join(ROOT, "evaluator"), os.path.join(tmp, "evaluator"),
                        ignore=shutil.ignore_patterns("__pycache__"))
        with zipfile.ZipFile(path) as zf:
            zf.extractall(tmp)
        code = "import submission.my_detector as m; print('imports ok:', m.MyDetector.__name__)"
        res = subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, '.'); " + code],
                             cwd=tmp, capture_output=True, text=True)
        print(res.stdout.strip() or res.stderr.strip())
        if res.returncode:
            sys.exit("check failed: the zip does not stand alone")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--scorecard", help="a run's scorecard.json, shipped as submission/scorecard.json")
    ap.add_argument("--check", action="store_true", help="unzip into a fresh folder and import the detector")
    args = ap.parse_args()
    path = build(args.scorecard)
    if args.check:
        check(path)


if __name__ == "__main__":
    main()
