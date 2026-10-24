"""Learn conservative declarations, never function bodies, from verified contributions.

Private output is bound to the reference image and every contributing source hash.
Conflicting or non-scalar declarations are excluded. No service or model calls.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / 'local/matched-knowledge.json'
TYPES = r'(?:unsigned\s+(?:char|short|int|long)|signed\s+char|char|short|int|long|float|double|bool|void\s*\*)'


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def declaration_text(text):
    """Keep declaration tokens, never text hidden in comments or literals."""
    pattern=r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
    return re.sub(pattern,lambda match:'\n'*match[0].count('\n')+' ',text,flags=re.S)


def declarations(text):
    text = declaration_text(text)
    pattern = r'\bextern\s+((?:(?:const|volatile)\s+)*' + TYPES + r')\s+([^;{}]+);'
    for match in re.finditer(pattern, text):
        kind = ' '.join(match[1].split()).replace(' *', '*')
        names = [n.strip() for n in match[2].split(',')]
        # Do not mistake arrays, function pointers or initialized data for scalars.
        if all(re.fullmatch(r'(?:DAT_|g_)[0-9a-fA-F]{8}', n) for n in names):
            for name in names:
                yield name.lower().replace('dat_', 'DAT_'), kind
    # Opaque global objects can supply their address without inventing a layout.
    # A defined tag supplies its identity only. Its fields/bases/body never enter
    # the library; an incomplete extern declaration suffices for address use.
    opaque = dict((name, tag) for tag, name in re.findall(r'\b(class|struct)\s+(\w+)\s*(?:;|\{|:)', text))
    for kind, name in re.findall(r'\bextern\s+(\w+)\s+(g_[0-9a-fA-F]{8})\s*;', text):
        if kind in opaque:
            yield name.lower(), opaque[kind] + ' ' + kind


def merge_types(kinds):
    """Qualifiers accumulate; incompatible base types fail closed."""
    bases = {re.sub(r'\b(?:const|volatile)\s+', '', k) for k in kinds}
    if len(bases) != 1:
        return None
    return ''.join(q + ' ' for q in ('const', 'volatile') if any(q in k.split() for k in kinds)) + bases.pop()


def contracts(text):
    """Only explicit cdecl scalar prototypes, never inferred from worker IDs/bodies."""
    text=declaration_text(text)
    pattern=r'^\s*(?:extern\s+(?:"C"\s+)?)?(void|int|unsigned\s+int|bool)\s+__cdecl\s+(FUN_[0-9a-fA-F]{8})\s*\(([^(){};]*)\)\s*;'
    for match in re.finditer(pattern,text,re.M):
        parameters=[];valid=True
        for parameter in ([] if match[3].strip() in ('','void') else match[3].split(',')):
            item=re.fullmatch(r'\s*(unsigned\s+int|int|bool)(?:\s+[A-Za-z_]\w*)?\s*',parameter)
            if not item:valid=False;break
            parameters.append(' '.join(item[1].split()))
        if valid and len(parameters)<=8:
            yield match[2].lower(),dict(return_type=' '.join(match[1].split()),argument_types=parameters)


def build(corpus, output=DEFAULT):
    report = read(corpus)
    settings = read(ROOT / 'local/settings.json')
    if sha(settings['checker_image']) != report['reference_sha256']:
        raise ValueError('Verified corpus belongs to a different reference image')
    found, sources, calls = {}, [], {}
    for row in report['results']:
        if not row.get('original_verified'):
            continue
        path = (ROOT / row['source']).resolve()
        pack = ROOT / 'work' / row['claim_id'] / 'pack.json'
        if not path.is_relative_to(ROOT / 'contributions') or sha(path).lower() != row['source_sha256'].lower():
            raise ValueError('Contribution identity/hash changed')
        if sha(pack) != row['pack_metadata_sha256']:
            raise ValueError('Verified context metadata changed')
        sources.append(dict(path=str(path.relative_to(ROOT)), sha256=sha(path),
                            pack=str(pack.relative_to(ROOT)),pack_metadata_sha256=sha(pack)))
        text=path.read_text(encoding='utf-8-sig')
        for name, kind in declarations(text):
            found.setdefault(name, {}).setdefault(kind, []).append(row['claim_id'])
        for name, contract in contracts(text):
            calls.setdefault(name,{}).setdefault(json.dumps(contract,sort_keys=True),[]).append(row['claim_id'])
    # Different aliases of one address must agree as well. Otherwise insertion
    # order could silently overwrite a conflicting declaration.
    by_address={}
    for name,kinds in found.items():
        address=name[4:] if name.startswith('DAT_') else name[2:]
        item=by_address.setdefault(address.lower(),dict(names=[],kinds={}))
        item['names'].append(name)
        for kind,evidence in kinds.items():item['kinds'].setdefault(kind,[]).extend(evidence)
    globals_, conflicts = {}, {}
    for address,item in sorted(by_address.items()):
        kinds=item['kinds'];name=sorted(item['names'],key=lambda n:(not n.startswith('DAT_'),n))[0]
        kind = merge_types(kinds)
        if kind:
            globals_[address] = dict(name=name, ctype=kind, evidence=kinds)
        else:
            conflicts[name] = kinds
    call_contracts={name[4:]:dict(**json.loads(next(iter(options))),evidence=next(iter(options.values())))
                    for name,options in calls.items() if len(options)==1}
    result = dict(version=1, reference_sha256=report['reference_sha256'], sources=sources,call_contracts=call_contracts,
                  conflicting_contracts={name:options for name,options in calls.items() if len(options)!=1},
                  scanned_contributions=len(sources), globals=globals_, conflicts=conflicts,
                  method='Scalar and opaque object declarations only; no saved function bodies or target-address solutions')
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    if sha(settings['checker_image'])!=report['reference_sha256']:
        raise ValueError('Reference image changed while building declarations')
    temporary=Path(output).with_suffix('.tmp')
    temporary.write_text(json.dumps(result, indent=2))
    os.replace(temporary,output)
    return result


def load_data(path=None):
    """Stale/corrupt optional knowledge disables this extension, not core patterns."""
    try:
        path=Path(path or os.environ.get('FNV_MATCHED_KNOWLEDGE',DEFAULT))
        data = read(path)
        if data['version'] != 1 or sha(read(ROOT / 'local/settings.json')['checker_image']) != data['reference_sha256']:
            return {}
        for source in data['sources']:
            p = (ROOT / source['path']).resolve()
            if not p.is_relative_to(ROOT / 'contributions') or sha(p) != source['sha256']:
                return {}
            if 'pack' in source:
                pack=(ROOT/source['pack']).resolve()
                if not pack.is_relative_to(ROOT/'work') or sha(pack)!=source['pack_metadata_sha256']:
                    return {}
        return data
    except (OSError, ValueError, KeyError, TypeError):
        return {}


def load(path=None):
    return load_data(path).get('globals',{})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, default=ROOT / 'local/benchmark/corpus-expansion/verified-corpus.json')
    parser.add_argument('--output', type=Path, default=DEFAULT)
    args = parser.parse_args()
    data = build(args.corpus, args.output)
    opaque=sum(v['ctype'].startswith(('class ','struct ')) for v in data['globals'].values())
    print(json.dumps(dict(scanned=data['scanned_contributions'], scalar_globals=len(data['globals'])-opaque,opaque_globals=opaque,
                         call_contracts=len(data['call_contracts']),conflicts=len(data['conflicts']),function_bodies_stored=0)))
