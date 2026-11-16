import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml
import zstandard


ROOT = Path(__file__).resolve().parents[1]


class RegionTitlesWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = yaml.load(
            (ROOT / '.github/workflows/region_titles.yml').read_text(encoding='utf-8'),
            Loader=yaml.BaseLoader,
        )
        cls.steps = cls.workflow['jobs']['build']['steps']

    def setUp(self):
        self.artifacts = [
            {'name': 'titledb', 'expired': False, 'expires_at': '2099-01-01T00:00:00Z'},
            {'name': 'titledb-state-example-key', 'expired': False,
             'expires_at': '2099-01-01T00:00:00Z'},
        ]

    def run_check(self, artifacts=None, runs=None, force=False):
        node = shutil.which('node')
        if not node:
            self.skipTest('Node.js is required to execute the GitHub Actions script')
        script = next(s['with']['script'] for s in self.steps if s.get('id') == 'updates')
        fixture = {
            'artifacts': self.artifacts if artifacts is None else artifacts,
            'runs': [{'id': 123}] if runs is None else runs,
            'force': force,
        }
        harness = r'''
const fixture = JSON.parse(process.argv[1]);
const script = process.argv[2];
Date.now = () => Date.parse('2030-01-01T00:00:00Z');
const result = {outputs: {}, queries: [], summaries: []};
process.env.BUILD_KEY = 'example-key';
process.env.FORCE_REBUILD = String(fixture.force);
const context = {repo: {owner: 'example', repo: 'fixture'}, ref: 'refs/heads/master'};
const github = {rest: {actions: {
  listWorkflowRuns: async params => {
    result.queries.push(params);
    return {data: {workflow_runs: fixture.runs}};
  },
  listWorkflowRunArtifacts: () => {},
}}, paginate: async (method, params) => {
  result.artifactQuery = params;
  return fixture.artifacts;
}};
const core = {
  setOutput: (key, value) => { result.outputs[key] = value; },
  info: () => {},
  summary: {addRaw: value => {
    result.summaries.push(value);
    return {write: async () => {}};
  }},
};
const AsyncFunction = Object.getPrototypeOf(async function() {}).constructor;
new AsyncFunction('github', 'context', 'core', script)(github, context, core)
  .then(() => process.stdout.write(JSON.stringify(result)))
  .catch(error => { console.error(error); process.exitCode = 1; });
'''
        completed = subprocess.run(
            [node, '-e', harness, json.dumps(fixture), script],
            capture_output=True, text=True, cwd=ROOT,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return json.loads(completed.stdout)

    def test_unchanged_sources_skip_build(self):
        result = self.run_check()
        self.assertEqual(result['outputs']['build'], 'false')
        self.assertEqual(result['queries'][0]['event'], 'schedule')
        self.assertEqual(result['queries'][0]['status'], 'success')
        self.assertEqual(result['queries'][0]['branch'], 'master')
        self.assertEqual(result['artifactQuery']['run_id'], 123)

    def test_changed_sources_or_workflow_rebuild(self):
        self.artifacts[1]['name'] = 'titledb-state-older-key'
        self.assertEqual(self.run_check()['outputs']['build'], 'true')

    def test_first_run_rebuilds(self):
        self.assertEqual(self.run_check(runs=[])['outputs']['build'], 'true')

    def test_missing_artifact_or_state_rebuilds(self):
        for artifacts in ([], self.artifacts[:1], self.artifacts[1:]):
            with self.subTest(artifacts=artifacts):
                self.assertEqual(self.run_check(artifacts=artifacts)['outputs']['build'], 'true')

    def test_expired_or_expiring_artifact_rebuilds(self):
        for index in (0, 1):
            for expires_at, expired in (
                ('2099-01-01T00:00:00Z', True),
                ('2000-01-01T00:00:00Z', False),
                ('2030-01-01T12:00:00Z', False),
            ):
                artifacts = [dict(a) for a in self.artifacts]
                artifacts[index].update(expires_at=expires_at, expired=expired)
                with self.subTest(index=index, expires_at=expires_at, expired=expired):
                    self.assertEqual(self.run_check(artifacts=artifacts)['outputs']['build'], 'true')

    def test_force_rebuild_bypasses_previous_runs(self):
        result = self.run_check(force=True)
        self.assertEqual(result['outputs']['build'], 'true')
        self.assertEqual(result['queries'], [])

    def test_every_expensive_step_is_gated_and_state_is_uploaded_last(self):
        check_index = next(i for i, s in enumerate(self.steps) if s.get('id') == 'updates')
        cancel = self.steps[check_index + 1]
        self.assertEqual(cancel['if'], "steps.updates.outputs.build == 'false'")
        self.assertIn('cancelWorkflowRun', cancel['with']['script'])
        self.assertIn('throw new Error', cancel['with']['script'])
        for step in self.steps[check_index + 2:]:
            self.assertEqual(step['if'], "steps.updates.outputs.build == 'true'")
        uploads = [s for s in self.steps if s.get('uses', '').startswith('actions/upload-artifact@')]
        self.assertEqual(uploads[0]['with']['name'], 'titledb')
        self.assertEqual(self.workflow['env']['TITLEDB_KEEP_PLAIN_JSON'], 'true')
        self.assertEqual(uploads[0]['with']['compression-level'],
                         "${{ env.TITLEDB_KEEP_PLAIN_JSON == 'true' && 9 || 0 }}")
        self.assertEqual(uploads[-1]['with']['name'],
                         'titledb-state-${{ steps.sources.outputs.build_key }}')
        self.assertEqual(self.workflow['concurrency']['cancel-in-progress'], 'false')

    def test_generated_json_compression_preserves_content_and_other_files(self):
        for keep_plain in ('true', 'false'):
            with self.subTest(keep_plain=keep_plain):
                self.check_generated_json_compression(keep_plain)

    def check_generated_json_compression(self, keep_plain):
        temporary_root = ROOT / '.tmp'
        temporary_root.mkdir(exist_ok=True)
        step = next(s for s in self.steps if s.get('name') == 'Compress generated JSON files')
        uploads = [s for s in self.steps if s.get('uses', '').startswith('actions/upload-artifact@')]
        self.assertLess(self.steps.index(step), self.steps.index(uploads[0]))
        with tempfile.TemporaryDirectory(dir=temporary_root) as directory:
            output = Path(directory) / 'nut' / 'build_artefacts'
            output.mkdir(parents=True)
            fixtures = {
                'titles.US.en.json': b'{"0100000000001000": {"name": "Example Title"}}',
                'cnmts-fixed.json': b'{}',
                'languages.json': b'{"US": ["en"]}',
                'versions.txt': b'id|version\n',
                'latest_example123': b'',
            }
            for filename, content in fixtures.items():
                (output / filename).write_bytes(content)
            result = subprocess.run([sys.executable, '-c', step['run']], cwd=directory,
                                    capture_output=True, text=True,
                                    env={**os.environ, 'TITLEDB_KEEP_PLAIN_JSON': keep_plain})
            self.assertEqual(result.returncode, 0, result.stderr)
            for filename, content in fixtures.items():
                if filename.endswith('.json'):
                    if keep_plain == 'true':
                        self.assertEqual((output / filename).read_bytes(), content)
                    else:
                        self.assertFalse((output / filename).exists())
                    compressed = (output / (filename + '.zst')).read_bytes()
                    self.assertEqual(zstandard.ZstdDecompressor().decompress(compressed), content)
                    self.assertEqual(compressed, zstandard.ZstdCompressor(level=9).compress(content))
                else:
                    self.assertEqual((output / filename).read_bytes(), content)
            self.assertFalse(list(output.glob('*.tmp')))

    def run_source_preparation(self, files, verify):
        temporary_root = ROOT / '.tmp'
        temporary_root.mkdir(exist_ok=True)
        script = next(s['run'] for s in self.steps
                      if s.get('name') == 'Prepare TitleDB source files')
        with tempfile.TemporaryDirectory(dir=temporary_root) as directory:
            source_dir = Path(directory) / 'nut' / 'titledb'
            source_dir.mkdir(parents=True)
            for filename, content in files.items():
                (source_dir / filename).write_bytes(content)
            result = subprocess.run(
                [sys.executable, '-c', script], cwd=directory,
                capture_output=True, text=True,
            )
            verify(result, source_dir)

    def source_fixture(self):
        return {
            'languages.json': b'{"US": ["en"], "JP": ["ja"]}',
            'US.en.json': b'{"1": {"name": "Example Title"}}',
            'JP.ja.json': b'{}',
            'cnmts.json': b'{}',
            'versions.json': b'{}',
            'versions.txt': b'id|version\n',
        }

    def test_source_preparation_supports_plain_compressed_and_mixed_files(self):
        expected = self.source_fixture()
        for mode in ('plain', 'compressed', 'mixed'):
            with self.subTest(mode=mode):
                files = {}
                for index, (filename, content) in enumerate(expected.items()):
                    if mode == 'compressed' or (mode == 'mixed' and index % 2 == 0):
                        # Streaming decompression must also support frames without a size header.
                        files[filename + '.zst'] = zstandard.ZstdCompressor(
                            write_content_size=False,
                        ).compress(content)
                    else:
                        files[filename] = content
                # The consolidated database must not become a seed for generation.
                files['titles.json.zst'] = zstandard.ZstdCompressor().compress(b'{}')

                def verify(result, source_dir):
                    self.assertEqual(result.returncode, 0, result.stderr)
                    for filename, content in expected.items():
                        self.assertEqual((source_dir / filename).read_bytes(), content)
                    self.assertFalse((source_dir / 'titles.json').exists())

                self.run_source_preparation(files, verify)

    def test_source_preparation_prefers_existing_json(self):
        files = self.source_fixture()
        files.update({filename + '.zst': b'invalid compressed data' for filename in files})

        def verify(result, source_dir):
            self.assertEqual(result.returncode, 0, result.stderr)
            for filename, content in self.source_fixture().items():
                self.assertEqual((source_dir / filename).read_bytes(), content)

        self.run_source_preparation(files, verify)

    def test_source_preparation_fails_for_missing_or_corrupt_sources(self):
        for filename in ('languages.json', 'US.en.json', 'cnmts.json', 'versions.txt'):
            for corrupt in (False, True):
                with self.subTest(filename=filename, corrupt=corrupt):
                    files = self.source_fixture()
                    del files[filename]
                    if corrupt:
                        files[filename + '.zst'] = b'invalid compressed data'

                    def verify(result, source_dir):
                        self.assertNotEqual(result.returncode, 0)
                        if not corrupt:
                            self.assertIn(filename, result.stderr)
                        self.assertFalse((source_dir / filename).exists())
                        self.assertFalse(list(source_dir.glob('*.tmp')))

                    self.run_source_preparation(files, verify)


if __name__ == '__main__':
    unittest.main()
