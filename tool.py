#!/usr/bin/env python3
"""Audit actual directory entry names for a conservative portable-path policy."""
import re
import unicodedata
from _support import Parser, Report, anchored, cli, guarded, limits, positive, walk
TOOL = "portable-path-audit"
RESERVED = re.compile(r"^(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])$", re.IGNORECASE)

@guarded(TOOL)
def audit(root, *, max_entries=100000, max_depth=64, max_component_units=255, max_findings=1000):
    limits(max_entries=max_entries,max_depth=max_depth,max_component_units=max_component_units,max_findings=max_findings)
    report = Report(TOOL,max_findings)
    count, groups = 0, {}
    with anchored(root, True) as fd:
        for rel, st, parent, name in walk(fd,max_entries,max_depth):
            count += 1
            folder = rel.rpartition("/")[0]
            if any(ord(c)<32 or c in '<>:"\\|?*' for c in name):
                report.add("windows_forbidden_character", path=rel)
            if name.endswith((" ",".")):
                report.add("trailing_space_or_dot", path=rel)
            stem = name.split(".",1)[0].rstrip(" ")
            if RESERVED.fullmatch(stem):
                report.add("windows_reserved_name",path=rel)
            try:
                units = len(name.encode("utf-16-le"))//2
            except UnicodeEncodeError:
                report.add("non_unicode_filename",path=rel)
                continue
            if units > max_component_units:
                report.add("component_unit_budget_exceeded",path=rel,utf16_units=units)
            nfc = unicodedata.normalize("NFC",name)
            if nfc != name:
                report.add("non_nfc_name",path=rel)
            key = folder, nfc.casefold()
            if key in groups:
                other = groups[key]
                report.add("case_or_nfc_collision",path=rel,other=other)
            else:
                groups[key]=rel
    return report.finish({"entries_scanned":count,"unicode_version":unicodedata.unidata_version})

def parse_and_audit():
    p=Parser(description=__doc__);p.add_argument("root")
    for name,default in [("max-entries",100000),("max-depth",64),("max-component-units",255),("max-findings",1000)]:
        p.add_argument("--"+name,type=positive,default=default)
    a=vars(p.parse_args());root=a.pop("root");return audit(root,**a)
if __name__=="__main__":raise SystemExit(cli(TOOL,parse_and_audit))
