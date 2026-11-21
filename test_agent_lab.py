"""Local synthetic Agent Lab runner qualification tests."""
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

from wolfalibi.agent_lab import ManifestError, ProbeError, SCHEMA, load_manifest, run_manifest, main


class AgentLabTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tmp_path = Path(self.tmp.name)
        self.manifest = self.tmp_path / 'manifest.json'
        self.report = self.tmp_path / 'report.json'
        self.initial = {
            'schema': SCHEMA, 'agent_type': 'custom',
            'entrypoint': {'module': 'examples.agent_lab_sample', 'callable': 'run'},
            'tools': [
                {'alias':'lookup','module':'examples.agent_lab_sample','callable':'lookup','surface':'tool','operation':'invoke'},
                {'alias':'denied','module':'examples.agent_lab_sample','callable':'denied','surface':'filesystem','operation':'read'},
            ], 'fixtures': {'query':'hello'}
        }
        self.save()

    def save(self, value=None):
        self.manifest.write_text(json.dumps(self.initial if value is None else value))

    def test_manifest_validation_does_not_import_agent(self):
        with patch('wolfalibi.agent_lab.importlib.import_module',side_effect=AssertionError('import occurred')):
            obj,digest=load_manifest(self.manifest)
        self.assertEqual(obj['schema'],SCHEMA)
        self.assertEqual(len(digest),64)

    def test_one_command_synthetic_agent_report(self):
        result=run_manifest(self.manifest,self.report,consent=True,allow_local_code=True)
        self.assertEqual(result['outcome'],'PASS')
        data=json.loads(self.report.read_text())
        self.assertEqual(data['counts'],{'filesystem.read.denied':1,'tool.invoke.success':1})
        self.assertEqual(result['events'],2)
        self.assertFalse(data['nonaccess_proof'])
        self.assertFalse(data['network_upload'])
        self.assertEqual(data['coverage'],'EXPLICITLY_WRAPPED_CALLS_ONLY')
        self.assertEqual(stat.S_IMODE(self.report.stat().st_mode),0o600)

    def test_consent_refuses_import(self):
        with patch('wolfalibi.agent_lab.importlib.import_module',side_effect=AssertionError('import occurred')):
            with self.assertRaises(ProbeError):
                run_manifest(self.manifest,self.report,consent=False,allow_local_code=True)
        self.assertFalse(self.report.exists())

    def test_local_code_opt_in_required(self):
        with patch('wolfalibi.agent_lab.importlib.import_module',side_effect=AssertionError('import occurred')):
            with self.assertRaises(ProbeError):
                run_manifest(self.manifest,self.report,consent=True,allow_local_code=False)

    def test_duplicate_json_fields_rejected(self):
        self.manifest.write_text('{"schema":"a","schema":"b"}')
        with self.assertRaisesRegex(ManifestError,'duplicate'):
            load_manifest(self.manifest)

    def test_extra_or_missing_schema_fields_rejected(self):
        invalid=dict(self.initial, surprise='unsupported')
        self.save(invalid)
        with self.assertRaises(ManifestError):load_manifest(self.manifest)
        invalid.pop('surprise')
        invalid.pop('fixtures')
        self.save(invalid)
        with self.assertRaises(ManifestError):load_manifest(self.manifest)

    def test_duplicate_alias_rejected(self):
        self.initial['tools'].append(dict(self.initial['tools'][0]))
        self.save()
        with self.assertRaises(ManifestError):load_manifest(self.manifest)

    def test_invalid_module_or_callable_rejected(self):
        self.initial['entrypoint']['module']='../../etc/passwd'
        self.save()
        with self.assertRaises(ManifestError):load_manifest(self.manifest)
        self.initial['entrypoint']['module']='examples.agent_lab_sample'
        self.initial['entrypoint']['callable']='__import__'
        self.save()
        with self.assertRaises(ManifestError):load_manifest(self.manifest)

    def test_invalid_category_and_unhashable_data_refused(self):
        self.initial['tools'][0]['surface']={'account':'secret'}
        self.save()
        with self.assertRaises(ManifestError):load_manifest(self.manifest)
        self.initial['tools'][0]['surface']='tool'
        self.initial['agent_type']={'customer':'secret'}
        self.save()
        with self.assertRaises(ManifestError):load_manifest(self.manifest)

    def test_oversized_and_invalid_fixture_refused(self):
        self.initial['fixtures']['query']='x'*2050
        self.save()
        with self.assertRaises(ManifestError):load_manifest(self.manifest)
        self.manifest.write_bytes(b'x'*32769)
        with self.assertRaises(ManifestError):load_manifest(self.manifest)

    def test_dry_run_never_imports(self):
        with patch('wolfalibi.agent_lab.importlib.import_module',side_effect=AssertionError('import occurred')):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                rc=main(['--manifest',str(self.manifest),'--dry-run'])
        self.assertEqual(rc,0)
        self.assertFalse(json.loads(output.getvalue())['imports_executed'])

    def test_local_cli_requires_two_explicit_flags(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            rc=main(['--manifest',str(self.manifest),'--output',str(self.report),'--consent'])
        self.assertEqual(rc,2)
        self.assertEqual(json.loads(output.getvalue())['outcome'],'BLOCKED')

    def test_existing_export_never_overwritten(self):
        self.report.write_text('existing')
        with self.assertRaises(FileExistsError):run_manifest(self.manifest,self.report,consent=True,allow_local_code=True)
        self.assertEqual(self.report.read_text(),'existing')

    def test_agent_exception_not_exposed(self):
        self.initial['entrypoint']['callable']='denied'
        self.save()
        result=run_manifest(self.manifest,self.report,consent=True,allow_local_code=True)
        self.assertEqual(result['outcome'],'AGENT_ERROR')
        self.assertNotIn('synthetic refusal',json.dumps(result))
        self.assertEqual(json.loads(self.report.read_text())['events'],0)

    def test_missing_module_blocked_without_import_exception_leak(self):
        self.initial['entrypoint']['module']='examples.module_does_not_exist'
        self.save()
        with contextlib.redirect_stdout(io.StringIO()) as output:
            rc=main(['--manifest',str(self.manifest),'--output',str(self.report),'--consent','--allow-local-code'])
        self.assertEqual(rc,2)
        self.assertEqual(json.loads(output.getvalue())['reason'],'ManifestError')

    def test_async_agent_and_tool(self):
        module_name='synthetic_lab_async_test'
        module_source='''
async def tool(x):
    return x + "!"
async def run(tools, fixtures):
    assert await tools["async_tool"](fixtures["query"]) == "hello!"
'''
        (self.tmp_path/(module_name+'.py')).write_text(module_source)
        sys.path.insert(0,str(self.tmp_path))
        self.addCleanup(lambda: sys.path.remove(str(self.tmp_path)))
        self.addCleanup(lambda: sys.modules.pop(module_name,None))
        self.initial['entrypoint']={'module':module_name,'callable':'run'}
        self.initial['tools']=[{'alias':'async_tool','module':module_name,'callable':'tool','surface':'model','operation':'request'}]
        self.save()
        result=run_manifest(self.manifest,self.report,consent=True,allow_local_code=True)
        self.assertEqual(result['outcome'],'PASS')
        self.assertEqual(json.loads(self.report.read_text())['counts'],{'model.request.success':1})

    def test_agent_arguments_and_return_values_not_in_report(self):
        self.initial['fixtures']['query']='VERY_PRIVATE_TEST_INPUT_NOT_FOR_EXPORT'
        self.save()
        # This agent fails its hard-coded synthetic assertion, but no fixture or error is emitted.
        result=run_manifest(self.manifest,self.report,consent=True,allow_local_code=True)
        self.assertEqual(result['outcome'],'AGENT_ERROR')
        self.assertNotIn('VERY_PRIVATE',self.report.read_text())
        self.assertNotIn('VERY_PRIVATE',json.dumps(result))

    def test_unknown_function_does_not_run_agent(self):
        self.initial['tools'][0]['callable']='unknown'
        self.save()
        with self.assertRaises(ManifestError):
            run_manifest(self.manifest,self.report,consent=True,allow_local_code=True)
        self.assertFalse(self.report.exists())


if __name__=='__main__':unittest.main(verbosity=2)
