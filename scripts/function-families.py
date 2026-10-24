"""Private structural catalog of local function packs and hash-verified sources.

Families suggest earlier solutions to an agent; similarity never proves a MATCH.
No claims, submissions, model calls, source rewriting or game execution.
"""
import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import capstone as cs
import pefile

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / 'local/benchmark/assist-pipeline/families.json'

def read(path): return json.loads(Path(path).read_text(encoding='utf-8-sig'))
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def private(path):
    path = Path(path).resolve()
    if not any(path.is_relative_to(ROOT / p) for p in ('work', 'local')):
        raise ValueError('Catalog output must stay in ignored local/ or work/')
    return path

def shape(data, address):
    """Ignore concrete registers/constants, retain operand widths and CFG shape."""
    decoder = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32); decoder.detail = True
    code = list(decoder.disasm(data, address))
    if not code or sum(i.size for i in code) != len(data) or len(code) > 256:
        raise ValueError('Incomplete or oversized instruction decode')
    positions = {i.address:n for n,i in enumerate(code)}
    registers = {}
    def reg(name):
        if not name: return None
        if name in ('esp', 'ebp'): return name
        if name not in registers: registers[name] = 'r' + str(len(registers))
        return registers[name]
    rows = []
    for item in code:
        operands = []
        for value in item.operands:
            if value.type == cs.x86.X86_OP_REG:
                operands.append(['reg', value.size, reg(item.reg_name(value.reg))])
            elif value.type == cs.x86.X86_OP_IMM:
                if item.group(cs.CS_GRP_JUMP):
                    operands.append(['branch', positions.get(value.imm, 'external')])
                elif item.mnemonic == 'call': operands.append(['call_target'])
                elif item.mnemonic == 'ret': operands.append(['cleanup', value.imm])
                else: operands.append(['constant', value.size, 'zero' if value.imm == 0 else 'nonzero'])
            elif value.type == cs.x86.X86_OP_MEM:
                mem = value.mem
                base = item.reg_name(mem.base)
                # Exact stack offsets are retained; field offsets deliberately
                # vary within a family and must be recovered for each target.
                displacement = mem.disp if base in ('esp','ebp') else ('zero' if mem.disp == 0 else 'field')
                operands.append(['memory', value.size, reg(base), reg(item.reg_name(mem.index)), mem.scale, displacement])
            else: operands.append(['unknown', value.size])
        rows.append([item.mnemonic, operands])
    key = hashlib.sha256(json.dumps(rows,separators=(',',':')).encode()).hexdigest()
    return key, len(code)

def build(limit=1000, output=DEFAULT):
    if not 1 <= limit <= 10000: raise ValueError('Limit must be 1..10000')
    output = private(output)
    submissions = defaultdict(list)
    for row in read(ROOT / 'local/submissions.json'):
        submissions[str(row.get('address','')).lower()].append(row)
    image_path = Path(read(ROOT / 'local/settings.json')['checker_image'])
    image = pefile.PE(str(image_path), fast_load=True)
    groups = defaultdict(list); seen = set(); errors = []
    files = sorted((ROOT / 'work').glob('clm_*/pack.json'),key=lambda p:p.stat().st_mtime,reverse=True)
    try:
        for file in files:
            if len(seen) >= limit: break
            try:
                meta = read(file); address = int(meta['address'],16); size = int(meta['size'])
                if address in seen or not 1 <= size <= 4096: continue
                seen.add(address)
                data = image.get_data(address-image.OPTIONAL_HEADER.ImageBase,size)
                if len(data) != size: raise ValueError('Incomplete reference span')
                key,count = shape(data,address)
                flags = meta.get('flags',[])
                family = hashlib.sha256((key+json.dumps(flags)).encode()).hexdigest()
                examples = []
                for receipt in submissions.get(meta['address'].lower(),[]):
                    source = (ROOT / receipt.get('source','')).resolve()
                    if not source.is_relative_to(ROOT / 'contributions') or not source.is_file(): continue
                    actual = sha(source)
                    if actual.lower() != str(receipt.get('source_sha256','')).lower(): continue
                    if receipt.get('checker_result') != 'MATCH': continue
                    examples.append(dict(source=str(source),source_sha256=actual,
                                         model=receipt.get('model'),submission_id=receipt.get('submission_id'),
                                         note='Recorded local MATCH/upload; server acceptance is separate'))
                groups[family].append(dict(pack=str(file.parent),claim_id=file.parent.name,
                    address=meta['address'],symbol=meta['symbol'],size=size,instructions=count,
                    pack_metadata_sha256=sha(file),signature=meta.get('signature'),flags=flags,
                    matched_examples=examples))
            except (ValueError,KeyError,OSError) as error:
                errors.append(dict(pack=str(file.parent),reason=str(error)[:200]))
    finally: image.close()
    result=dict(version=1,utc=datetime.now(timezone.utc).isoformat(),reference_sha256=sha(image_path),
                packs=len(seen),family_count=len(groups),repeated_families=sum(len(g)>1 for g in groups.values()),
                families=dict(groups),errors=errors,confirmed_match=False,uploaded=0,model_calls=0,
                limitation='Structural hints only. Each new function needs its own source, context and official MATCH.')
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(result,indent=2))
    return result

def suggest(pack, catalog=DEFAULT, limit=3):
    pack=Path(pack).resolve(); meta=read(pack/'pack.json')
    if not pack.is_relative_to(ROOT/'work'): raise ValueError('Expected original private pack')
    if not 1<=limit<=20: raise ValueError('Suggestion limit must be1..20')
    data=read(private(catalog))
    if sha(Path(read(ROOT/'local/settings.json')['checker_image'])) != data['reference_sha256']:
        return dict(suggestions=[],reason='Private reference changed; rebuild catalog',confirmed_match=False)
    # Catalog identity is explicit; stale metadata never supplies source evidence.
    for family,rows in data['families'].items():
        own=next((r for r in rows if int(r['address'],16)==int(meta['address'],16)),None)
        if not own: continue
        if own['pack_metadata_sha256'] != sha(pack/'pack.json'):
            return dict(suggestions=[],reason='Target context changed; rebuild catalog')
        suggestions=[]
        for row in sorted(rows,key=lambda r:not bool(r['matched_examples'])):
            if int(row['address'],16)==int(meta['address'],16): continue
            sibling=Path(row['pack']).resolve(); sibling_meta=sibling/'pack.json'
            if not sibling.is_relative_to(ROOT/'work') or not sibling_meta.is_file(): continue
            if sha(sibling_meta)!=row['pack_metadata_sha256']: continue
            current=read(sibling_meta)
            if any(current.get(k)!=row.get(k) for k in ('address','symbol','size','flags')): continue
            examples=[]
            for e in row['matched_examples']:
                source=Path(e['source']).resolve()
                if source.is_relative_to(ROOT/'contributions') and source.is_file() and sha(source)==e['source_sha256']:
                    examples.append(e)
            if not examples: continue
            suggestions.append(dict(family=family,pack=row['pack'],symbol=row['symbol'],examples=examples,
                                    requires_target_specific_reconstruction=True))
            if len(suggestions)>=limit: break
        return dict(suggestions=suggestions,reason='Same normalized instruction shape and compiler flags; inspect context before reuse',confirmed_match=False)
    return dict(suggestions=[],reason='Pack not cataloged; rebuild catalog',confirmed_match=False)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__); sub=parser.add_subparsers(dest='command',required=True)
    p=sub.add_parser('build');p.add_argument('--limit',type=int,default=1000);p.add_argument('--output',type=Path,default=DEFAULT)
    p=sub.add_parser('suggest');p.add_argument('--pack',type=Path,required=True);p.add_argument('--catalog',type=Path,default=DEFAULT)
    args=parser.parse_args()
    result=build(args.limit,args.output) if args.command=='build' else suggest(args.pack,args.catalog)
    if args.command=='build': result={k:v for k,v in result.items() if k!='families'}
    print(json.dumps(result,indent=2))
