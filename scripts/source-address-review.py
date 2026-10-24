"""Conservative pre-upload screen; official compiler/checker still required.

Numeric literals inside the private executable's address range require review.
Comments and strings are ignored. This catches literal addresses that can pass
byte comparison while violating the contribution source rules.
"""
import json
import re
import sys
from pathlib import Path
import pefile

root=Path(__file__).resolve().parents[1]
settings=json.loads((root/'local/settings.json').read_text(encoding='utf-8-sig'))
pe=pefile.PE(settings['checker_image'],fast_load=True)
lower=pe.OPTIONAL_HEADER.ImageBase
upper=lower+pe.OPTIONAL_HEADER.SizeOfImage
pe.close()
source=Path(sys.argv[1]).read_text(encoding='utf-8-sig')
source=re.sub(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', ' ',source,flags=re.S)
literals=re.findall(r'(?<![\w.])(?:0[xX][0-9a-fA-F]+|[0-9]+)(?:[uUlL]*)(?![\w.])',source)
flagged=[]
for token in literals:
    raw=re.sub(r'[uUlL]+$','',token)
    value=int(raw,16 if raw.lower().startswith('0x') else 10)
    if lower<=value<upper:flagged.append(token)
print(json.dumps(dict(review_required=bool(flagged),numeric_literals=flagged)))
sys.exit(1 if flagged else 0)
