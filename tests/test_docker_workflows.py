import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / '.github' / 'workflows'


def read_workflow(name):
    return yaml.load((WORKFLOWS / name).read_text(encoding='utf-8'), Loader=yaml.BaseLoader)


def run_script(script, root, env):
    bash = shutil.which('bash')
    if os.name == 'nt':
        candidate = Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Git/bin/bash.exe'
        bash = str(candidate) if candidate.is_file() else bash
    if not bash:
        raise unittest.SkipTest('Bash is required for workflow shell checks')
    # Stub external commands; execute the actual workflow shell script.
    preamble = '''
git() { printf 'v1.2.3-4-gabcdef0\\n'; }
docker() {
  printf '%s\\n' "$*" >> "$TEST_DOCKER_LOG"
  if [[ "$3" == inspect ]]; then printf '%s\\n' "$TEST_MANIFEST"; fi
}
'''
    path = root / 'script.sh'
    path.write_text(preamble + script, encoding='utf-8')
    return subprocess.run([bash, '-e', '-o', 'pipefail', path.as_posix()], cwd=root,
                          env=dict(os.environ, **env), capture_output=True, text=True)


class DockerWorkflowTests(unittest.TestCase):
    def setUp(self):
        (ROOT / '.tmp').mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=ROOT / '.tmp', prefix='workflow-tests-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.shared = read_workflow('docker-native-build.yml')
        self.env = {
            'RUNNER_TEMP': self.root.as_posix(), 'GITHUB_OUTPUT': (self.root / 'output').as_posix(),
            'GITHUB_STEP_SUMMARY': (self.root / 'summary').as_posix(),
            'GITHUB_REF': 'refs/tags/v1.2.3', 'GITHUB_REF_NAME': 'dev',
            'GITHUB_SHA': 'abcdef0123456789', 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '2',
            'VALIDATION_ONLY': 'false', 'IMAGE': 'luketanti/aerofoil',
            'IMAGE_TAGS': 'luketanti/aerofoil:dev\nluketanti/aerofoil:sha-abcdef0',
            'TEST_DOCKER_LOG': (self.root / 'docker-log').as_posix(),
            'TEST_MANIFEST': json.dumps({'manifests': [
                {'platform': {'os': 'linux', 'architecture': arch}} for arch in ('amd64', 'arm64')
            ]}),
        }

    def metadata(self, name):
        workflow = read_workflow(name)
        script = workflow['jobs']['metadata']['steps'][-1]['run']
        result = run_script(script, self.root, self.env)
        self.assertEqual(result.returncode, 0, result.stderr)
        return (self.root / 'output').read_text()

    def test_native_runner_matrix_and_publish_gate(self):
        matrix = self.shared['jobs']['build']['strategy']['matrix']['include']
        self.assertEqual({m['arch']: m['runner'] for m in matrix},
                         {'amd64': 'ubuntu-24.04', 'arm64': 'ubuntu-24.04-arm'})
        self.assertEqual(self.shared['jobs']['publish']['needs'], 'build')
        self.assertNotIn('if', self.shared['jobs']['publish'])
        build_steps = self.shared['jobs']['build']['steps']
        self.assertLess(next(i for i, s in enumerate(build_steps) if 'runtime' in s['name']),
                        next(i for i, s in enumerate(build_steps) if s['name'] == 'Upload verified digest'))

    def test_branch_tags_are_preserved(self):
        output = self.metadata('docker-image-dev.yml')
        self.assertIn('version=v1.2.3-4-gabcdef0-dev', output)
        self.assertIn('luketanti/aerofoil:dev\nluketanti/aerofoil:sha-abcdef0', output)

    def test_validation_only_uses_unique_tag(self):
        self.env.update(VALIDATION_ONLY='true', GITHUB_REF_NAME='fixture-branch')
        output = self.metadata('docker-image-dev.yml')
        self.assertIn('luketanti/aerofoil:validation-123-2', output)
        self.assertNotIn('luketanti/aerofoil:dev', output)
        self.assertIn('validation', read_workflow('docker-image-dev.yml')['concurrency']['group'])

    def test_other_branches_cannot_publish_dev(self):
        self.env['GITHUB_REF_NAME'] = 'fixture-branch'
        script = read_workflow('docker-image-dev.yml')['jobs']['metadata']['steps'][-1]['run']
        self.assertNotEqual(run_script(script, self.root, self.env).returncode, 0)

    def test_release_tags_are_preserved(self):
        output = self.metadata('docker-image.yml')
        for tag in ('latest', '1.2.3', '1', '1.2', 'sha-abcdef0'):
            self.assertIn('luketanti/aerofoil:' + tag + '\n', output)

    def test_prerelease_keeps_major_and_minor_tags(self):
        self.env['GITHUB_REF'] = 'refs/tags/v1.2.3-beta.1'
        output = self.metadata('docker-image.yml')
        self.assertIn('luketanti/aerofoil:1.2\n', output)
        self.assertIn('luketanti/aerofoil:1.2.3-beta.1\n', output)

    def publish(self):
        script = self.shared['jobs']['publish']['steps'][-1]['run']
        return run_script(script, self.root, self.env)

    def digests(self):
        directory = self.root / 'digests'
        directory.mkdir()
        for arch, digit in [('amd64', 'a'), ('arm64', 'b')]:
            (directory / arch).write_text('sha256:' + digit * 64)

    def assert_no_publication(self):
        result = self.publish()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'docker-log').exists())

    def test_publish_uses_both_digests_and_all_tags(self):
        self.digests()
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        log = (self.root / 'docker-log').read_text()
        self.assertIn('--tag luketanti/aerofoil:dev --tag luketanti/aerofoil:sha-abcdef0', log)
        for digit in ('a', 'b'):
            self.assertIn('luketanti/aerofoil@sha256:' + digit * 64, log)

    def test_missing_architecture_blocks_publication(self):
        self.digests()
        (self.root / 'digests/arm64').unlink()
        self.assert_no_publication()

    def test_invalid_digest_blocks_publication(self):
        self.digests()
        (self.root / 'digests/arm64').write_text('invalid digest')
        self.assert_no_publication()

    def test_foreign_image_tag_blocks_publication(self):
        self.digests()
        self.env['IMAGE_TAGS'] += '\nexample/other:latest'
        self.assert_no_publication()

    def test_incomplete_manifest_fails_verification(self):
        self.digests()
        self.env['TEST_MANIFEST'] = json.dumps({'manifests': [
            {'platform': {'os': 'linux', 'architecture': 'amd64'}}
        ]})
        self.assertNotEqual(self.publish().returncode, 0)