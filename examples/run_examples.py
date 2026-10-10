"""Synthetic examples; all fixtures live in an automatically removed temporary directory."""
from pathlib import Path
import json, subprocess, sys, tempfile
TOOL=Path(__file__).resolve().parents[1]/"tool.py"
def run(expected,*args):
    r=subprocess.run([sys.executable,str(TOOL),*map(str,args)],capture_output=True,text=True)
    assert r.returncode==expected,(r.returncode,r.stdout,r.stderr)
    print(r.stdout.strip())
with tempfile.TemporaryDirectory() as tmp:
    p=Path(tmp)
    good=p/"good";bad=p/"bad";good.mkdir();bad.mkdir()
    (good/"readme.txt").write_text("synthetic\n");(bad/"CON.txt").write_text("synthetic\n")
    run(0,good);run(1,bad)
