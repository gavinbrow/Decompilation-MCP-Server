"""Extract a bounded authenticated data pack, rejecting paths and links."""
import argparse,tarfile
from pathlib import Path
def extract(archive,destination):
    destination=destination.resolve()
    with tarfile.open(archive,'r:gz') as stream:
        members=stream.getmembers()
        if len(members)>20000 or sum(m.size for m in members)>512*1024**2: raise ValueError('Pack exceeds extraction budget')
        for m in members:
            target=(destination/m.name).resolve()
            if not target.is_relative_to(destination) or ':' in m.name or '\\' in m.name or m.name.startswith('/') or not (m.isdir() or m.isfile()):
                raise ValueError('Unsafe pack path/link/type')
        stream.extractall(destination,members=members,filter='data')
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',type=Path);p.add_argument('destination',type=Path);a=p.parse_args();extract(a.archive,a.destination)
