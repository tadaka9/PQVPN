from __future__ import annotations

import main


def test_parser_builds() -> None:
    p = main.build_parser()
    # Ensure subcommands exist
    sub = p._subparsers
    assert sub is not None


def test_version_command_runs(capsys) -> None:
    rc = main.main(["version"])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    assert out == main.__version__
