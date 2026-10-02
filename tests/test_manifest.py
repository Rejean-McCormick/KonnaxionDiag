from pathlib import Path
from diagcore.manifest import load_manifest,validate_manifest
ROOT=Path(__file__).resolve().parents[1]

def test_manifest_is_valid():
    m=load_manifest(ROOT);assert validate_manifest(m)==[]

def test_taxonomy_preserved_and_s04w_added():
    m=load_manifest(ROOT);ids=[x['id'] for x in m['levels']]
    assert [f'N{i:02d}' for i in range(12)]==[x for x in ids if x.startswith('N')]
    assert all(f'S{i:02d}' in ids for i in range(15));assert 'S04W' in ids

def test_release_all_order_and_independent_security_gate():
    m=load_manifest(ROOT);levels=m['campaigns']['release-all']['levels']
    assert levels[:12]==[f'N{i:02d}' for i in range(12)]
    assert levels[12:18]==['S00','S01','S02','S03','S04','S04W']
    assert levels[-1]=='S14';assert m['campaigns']['release-all']['final_release_gate'] is True
