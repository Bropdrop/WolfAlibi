"""Identify the reviewed Git checkout used for an operator's synthetic trial."""

from pathlib import Path
import subprocess


def source_revision():
    root = Path(__file__).resolve().parents[1]

    def git(*args):
        return subprocess.run(["git", "-C", str(root), *args], check=True,
                              capture_output=True, text=True).stdout.strip()

    try:
        if Path(git("rev-parse", "--show-toplevel")).resolve() != root:
            raise ValueError("trial requires a WolfAlibi source checkout")
        git("ls-files", "--error-unmatch", "--", "wolfalibi/voidcell003_revision.py")
        if git("status", "--porcelain=v1", "--untracked-files=all"):
            raise ValueError("trial evidence requires a clean source checkout")
        commit, tree = git("rev-parse", "HEAD", "HEAD^{tree}").splitlines()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError("trial source revision unavailable") from exc
    return {"commit": commit, "tree": tree}
