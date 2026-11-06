"""Verify generated executive-summary PDF and its evidence-based content.

Uses ReportLab's own Paragraph text rather than adding a PDF-reader dependency.
"""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import reporting


class ExecutiveSummaryPDFTests(unittest.TestCase):
    def generate(self, records, severity, observation, recommendation, status='ok'):
        result = {
            'domain': 'nonprofit.example',
            'scanned_utc': '2026-11-06T12:00:00Z',
            'disclaimer': 'Public DNS evidence is not a mailbox security audit.',
            'raw_evidence': {
                'DMARC': {'status': status, 'values': records},
            },
            'findings': [{
                'control': 'DMARC', 'severity': severity,
                'observation': observation, 'recommendation': recommendation,
            }],
        }
        captured = []
        original_build = reporting.SimpleDocTemplate.build

        def record_build(document, flowables, *args, **kwargs):
            if Path(document.filename).name == '01_Executive_Summary.pdf':
                captured.extend(
                    item.getPlainText() for item in flowables
                    if hasattr(item, 'getPlainText')
                )
            return original_build(document, flowables, *args, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            with patch.object(reporting.SimpleDocTemplate, 'build', record_build):
                zip_path = reporting.package(result, root=directory)
            pdf_path = Path(zip_path).with_suffix('') / '01_Executive_Summary.pdf'
            self.assertTrue(pdf_path.is_file(), 'Executive Summary PDF missing')
            self.assertTrue(pdf_path.read_bytes().startswith(b'%PDF-'))
            self.assertGreater(pdf_path.stat().st_size, 500)
        return '\n'.join(captured)

    def test_monitoring_policy_evidence_and_recommendation(self):
        record = 'v=DMARC1; p=none; pct=25; rua=mailto:dmarc@nonprofit.example'
        content = self.generate(
            [record], 'Medium', 'DMARC monitoring only.',
            'Review sending services before increasing enforcement.'
        )
        for expected in (
            'Executive Risk Summary', 'monitoring-only',
            'Published policy (p): none',
            'Enforcement percentage (pct): 25',
            'mailto:dmarc@nonprofit.example', record,
            'DMARC monitoring only.',
            'Review sending services before increasing enforcement.',
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, content)

    def test_quarantine_and_reject_policies(self):
        for policy in ('quarantine', 'reject'):
            with self.subTest(policy=policy):
                content = self.generate(
                    ['v=DMARC1; p=' + policy], 'Low',
                    'Policy present.', 'Monitor authorized senders.'
                )
                self.assertIn('Published policy (p): ' + policy, content)
                self.assertIn('domain requests ' + policy, content)

    def test_missing_record(self):
        content = self.generate(
            [], 'High', 'No DMARC policy found.',
            'Publish a monitored DMARC policy.', status='no_answer'
        )
        self.assertIn('No DMARC TXT record returned.', content)
        self.assertIn('DNS lookup did not complete successfully', content)
        self.assertIn('Publish a monitored DMARC policy.', content)

    def test_high_severity_does_not_claim_valid_enforcement(self):
        content = self.generate(
            ['v=DMARC1; p=reject; pct=invalid'], 'High',
            'Invalid enforcement percentage.', 'Correct pct value.'
        )
        self.assertIn('high-severity finding', content)
        self.assertIn('Correct pct value.', content)
        self.assertNotIn('domain requests rejection', content)


if __name__ == '__main__':
    unittest.main()
