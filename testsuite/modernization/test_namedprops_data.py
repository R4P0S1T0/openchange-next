"""The shared LDB/SQL seed source must not alias named properties to one ID."""
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class NamedPropertyDataTests(unittest.TestCase):
    def test_generated_seed_ids_and_identities_are_unique(self):
        with tempfile.TemporaryDirectory(prefix='openchange-namedprops-data-') as directory:
            subprocess.run(['perl', str(ROOT / 'libmapi/conf/mparse.pl'),
                            '--parser=mapistore_namedprops_python', '--outputdir=' + directory,
                            str(ROOT / 'libmapi/conf/mapi-named-properties')],
                           check=True, capture_output=True)
            rows = runpy.run_path(str(Path(directory) / 'mapistore_namedprops.py'))['named_properties']
        ids = [p['mappedId'] for p in rows]
        identities = [(p['type'], p['oleguid'], p.get('propName') if p['type'] == 1 else p['propId'])
                      for p in rows]
        self.assertGreater(len(rows), 700)
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(identities), len(set(identities)))
        self.assertTrue(all(0x8000 <= id <= 0xfffe for id in ids))
