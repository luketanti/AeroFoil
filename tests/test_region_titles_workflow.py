import json
from pathlib import Path
import shutil
import subprocess
import unittest

import yaml


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
        self.assertEqual(uploads[-1]['with']['name'],
                         'titledb-state-${{ steps.sources.outputs.build_key }}')
        self.assertEqual(self.workflow['concurrency']['cancel-in-progress'], 'false')


if __name__ == '__main__':
    unittest.main()
