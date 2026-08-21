"""Parser for SELinux AVC denials in the system log.

A denial is the kernel refusing an operation the SELinux policy doesn't
allow. Real lines from a Pixel bugreport:

    ... W GrallocUploadTh: type=1400 audit(0.0:174): avc:  denied  { read } for
        name="uevent" dev="sysfs" ino=32559 scontext=u:r:platform_app:s0:c512,c768
        tcontext=u:object_r:sysfs:s0 tclass=file permissive=0 app=com.google.android...

    ... I auditd  : type=1400 audit(0.0:155): avc:  denied  { search } for
        comm="binder:7336_1" name="com.google.android.gms" dev="dm-61" ino=8631
        scontext=u:r:bluetooth:s0 tcontext=u:object_r:privapp_data_file:s0:c512,c768
        tclass=dir permissive=0

The single most load-bearing field is `permissive`:

  permissive=0  ENFORCING -- the operation was actually BLOCKED. Something
                did not work. This is a real functional failure.
  permissive=1  PERMISSIVE -- logged only; the operation succeeded anyway.
                Useful as a warning that it WOULD break once enforced, but
                nothing is broken right now.

Conflating those two is the main way SELinux analysis goes wrong, so they
are parsed as a distinct field and never flattened into "a denial happened".

Context strings are `user:role:type:sensitivity[:categories]`; the `type`
component (3rd field) is the part that identifies the domain/object -- e.g.
`u:r:platform_app:s0:c512,c768` -> `platform_app`. Categories vary per-app
instance and are deliberately dropped from the parsed type so the same
denial from two app instances groups together.
"""
from __future__ import annotations

import re

from app.parsers.base import SelinuxDenial, SourceRef
from app.parsers.section_extractor import Section

# Matches the logcat prefix plus the avc payload. `avc:` is followed by two
# spaces in real output, but the pattern tolerates any run of whitespace.
AVC_LINE_RE = re.compile(
    r"^(?P<ts>\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+\S+\s+\d+\s+\d+ "
    r"(?P<level>[VDIWEF]) (?P<tag>\S+)\s*:.*?avc:\s+(?P<verdict>denied|granted)\s+"
    r"\{\s*(?P<perms>[^}]+?)\s*\}\s+for\s+(?P<rest>.*)$"
)

_FIELD_RES = {
    "comm": re.compile(r'\bcomm="([^"]*)"'),
    "name": re.compile(r'\bname="([^"]*)"'),
    "app": re.compile(r"\bapp=(\S+)"),
    "tclass": re.compile(r"\btclass=(\S+)"),
    "scontext": re.compile(r"\bscontext=(\S+)"),
    "tcontext": re.compile(r"\btcontext=(\S+)"),
    "permissive": re.compile(r"\bpermissive=(\d)"),
}


def _context_type(context: str | None) -> str | None:
    """`u:r:platform_app:s0:c512,c768` -> `platform_app`. Returns the raw
    string unchanged if it isn't in the expected colon-separated shape,
    rather than guessing."""
    if not context:
        return None
    parts = context.split(":")
    return parts[2] if len(parts) >= 3 else context


def parse_selinux_denials(section: Section) -> list[SelinuxDenial]:
    out: list[SelinuxDenial] = []
    for i, raw in enumerate(section.lines):
        m = AVC_LINE_RE.match(raw)
        if not m:
            continue
        rest = m.group("rest")
        fields = {}
        for key, regex in _FIELD_RES.items():
            fm = regex.search(rest)
            fields[key] = fm.group(1) if fm else None

        permissive_raw = fields["permissive"]
        abs_line = section.line_start + i
        out.append(SelinuxDenial(
            timestamp=m.group("ts"),
            verdict=m.group("verdict"),
            # "{ read write }" -> ["read", "write"]
            permissions=m.group("perms").split(),
            source_context=fields["scontext"],
            source_domain=_context_type(fields["scontext"]),
            target_context=fields["tcontext"],
            target_type=_context_type(fields["tcontext"]),
            target_class=fields["tclass"],
            comm=fields["comm"],
            target_name=fields["name"],
            app=fields["app"],
            # None (not False) when the field is absent -- "we don't know if
            # this was enforced" is a different claim from "it wasn't".
            enforcing=(permissive_raw == "0") if permissive_raw is not None else None,
            source_ref=SourceRef(section.name, abs_line, abs_line),
        ))
    return out
