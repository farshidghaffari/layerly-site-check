import contextlib,io,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from sitecheck.cli import main

class PublicCLI(unittest.TestCase):
    def test_live_is_explicit(self):
        with contextlib.redirect_stderr(io.StringIO()):self.assertEqual(main(['check','https://example.com']),2)
    def test_offline_demo_and_validation(self):
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/'report.json'
            self.assertEqual(main(['demo','--out',str(target)]),0)
            self.assertTrue(json.loads(target.read_text(encoding='utf-8'))['is_sample'])
            with contextlib.redirect_stdout(io.StringIO()):self.assertEqual(main(['validate',str(target)]),0)
    def test_no_explanation_module_shipped(self):
        self.assertFalse((Path(__file__).resolve().parent.parent/'sitecheck/explain').exists())
