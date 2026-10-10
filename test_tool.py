import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).parent))
spec=importlib.util.spec_from_file_location("audit_tool",Path(__file__).with_name("tool.py"))
tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)
class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def codes(self,result):return {x["code"] for x in result.get("findings",[])}
    def call(self,*args):
        result=subprocess.run([sys.executable,str(Path(__file__).with_name("tool.py")),*map(str,args)],capture_output=True,text=True)
        return result.returncode,json.loads(result.stdout)
    def test_bad_cli(self):
        code,result=self.call("--unknown");self.assertEqual(code,2);self.assertEqual(result["status"],"error")
    def test_examples(self):
        result=subprocess.run([sys.executable,str(Path(__file__).parent/"examples"/"run_examples.py")],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        reports=[json.loads(x) for x in result.stdout.splitlines()]
        self.assertEqual([r["status"] for r in reports],["pass","findings"])

    def test_pass_and_cli(self):
        (self.root/'good.txt').write_text('x');self.assertEqual(tool.audit(self.root)['status'],'pass');self.assertEqual(self.call(self.root)[0],0)
    def test_windows_names(self):
        for n in ['CON.txt','LPT¹.log','bad:name','space ','dot.']:(self.root/n).touch()
        self.assertTrue({'windows_reserved_name','windows_forbidden_character','trailing_space_or_dot'}<=self.codes(tool.audit(self.root)))
        self.assertEqual(self.call(self.root)[0],1)
    def test_case_and_unicode(self):
        for n in ['Readme','README','é','e\u0301']:(self.root/n).touch()
        r=tool.audit(self.root);self.assertIn('case_or_nfc_collision',self.codes(r));self.assertIn('non_nfc_name',self.codes(r))
    def test_symlink_not_traversed(self):
        other=self.root/'outside';other.mkdir();(other/'CON').touch()
        scan=self.root/'scan';scan.mkdir();(scan/'link').symlink_to(other,target_is_directory=True)
        self.assertEqual(tool.audit(scan)['summary']['entries_scanned'],1)
        self.assertEqual(tool.audit(scan)['status'],'pass');self.assertEqual(tool.audit(scan/'link')['status'],'error')
    def test_limits_and_permission(self):
        (self.root/'a').touch();(self.root/'b').touch()
        self.assertEqual(tool.audit(self.root,max_entries=1)['status'],'error')
        self.assertEqual(tool.audit(self.root,max_entries=0)['status'],'error')
        with mock.patch.object(tool,'walk',side_effect=PermissionError):self.assertEqual(tool.audit(self.root)['status'],'error')
    def test_depth_units_and_finding_cap(self):
        (self.root/'long').touch();self.assertIn('component_unit_budget_exceeded',self.codes(tool.audit(self.root,max_component_units=2)))
        (self.root/'CON').touch();(self.root/'NUL').touch();r=tool.audit(self.root,max_findings=1);self.assertTrue(r['findings_truncated'])
        d=self.root/'a'/'b';d.mkdir(parents=True);self.assertEqual(tool.audit(self.root,max_depth=1)['status'],'error')

    def test_support_rejects_symlink_before_dotdot(self):
        import _support
        (self.root/'actual').mkdir();(self.root/'alias').symlink_to('actual');(self.root/'safe').write_bytes(b'x')
        with self.assertRaises((OSError,_support.InputError)):
            with _support.anchored(str(self.root)+'/alias/../safe'):
                self.fail('must not normalize away a symlink component')
    def test_support_detects_pre_read_mutation(self):
        import _support
        p=self.root/'changed';p.write_bytes(b'a');before=p.stat();p.write_bytes(b'longer')
        with _support.anchored(self.root,True) as fd:
            with self.assertRaises(_support.InputError):_support.read_at(fd,'changed',before,100)
    def test_support_entry_budget_and_host_guard(self):
        import _support
        (self.root/'a').mkdir();(self.root/'a'/'x').touch();(self.root/'b').touch()
        with _support.anchored(self.root,True) as fd:
            with self.assertRaises(_support.InputError):list(_support.walk(fd,max_entries=2))
        with mock.patch.object(_support.os,'name','unsupported'):
            with self.assertRaises(_support.InputError):_support._flags()

if __name__=="__main__":unittest.main()
