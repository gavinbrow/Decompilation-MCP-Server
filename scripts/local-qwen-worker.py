"""Private context/preparation helpers. No model calls or scheduler."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))

def inside(path, parent):
    path = path.resolve()
    path.relative_to(parent.resolve())
    return path

def context(pack):
    import pefile
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    manifest = read(pack / 'pack.json')
    packet = read(pack / 'packet.json')
    settings = read(ROOT / 'local/settings.json')
    image_path = settings.get('checker_image')
    if not image_path:
        raise RuntimeError('Private checker_image is not configured')
    pe = pefile.PE(image_path, fast_load=True)
    address = int(str(manifest['address']), 0)
    data = pe.get_data(address - pe.OPTIONAL_HEADER.ImageBase, int(manifest['size']))
    listing = '\n'.join(f'{i.address:08x}: {i.mnemonic} {i.op_str}'
                        for i in Cs(CS_ARCH_X86, CS_MODE_32).disasm(data, address))
    pe.close()
    files = [manifest['source'], *manifest.get('headers', [])]
    sources = []
    for name in files:
        path = inside(pack / name, pack)
        sources.append(f'FILE {name}\n{path.read_text(encoding="utf-8-sig")}')
    metadata = {key: packet.get(key, manifest.get(key)) for key in
                ('symbol', 'signature', 'address', 'size', 'flags', 'rules', 'tips')}
    tips = (ROOT / 'local/shared/compiler_tips.md').read_text(encoding='utf-8-sig')
    return tips + '\nCONTEXT:\n' + json.dumps(metadata) + '\n' + '\n'.join(sources) + '\nTARGET:\n' + listing
