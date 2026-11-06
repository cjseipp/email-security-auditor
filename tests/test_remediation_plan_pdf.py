"""Regression tests for the evidence-based Remediation Action Plan PDF.

Captures text passed to ReportLab while still writing and checking the real PDF.
No third-party PDF text extractor is required.
"""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import reporting


class RemediationPlanPDFTests(unittest.TestCase):
    def generate(self, records, severity='Medium', observation='DMARC monitoring only.',
                 recommendation='Validate senders before enforcement.', status='ok',
                 other_findings=None):
        findings = [{
            'control': 'DMARC', 'severity': severity,
            'observation': observation, 'recommendation': recommendation,
        }] + (other_findings or [])
        result = {
            'domain': 'nonprofit.example',
            'scanned_utc': '2026-11-06T12:00:00Z',
            'disclaimer': 'Public DNS evidence is not a mailbox audit.',
            'raw_evidence': {'DMARC': {'status': status, 'values': records}},
            'findings': findings,
        }
        captured = []
        original_build = reporting.SimpleDocTemplate.build

        def record_build(document, flowables, *args, **kwargs):
            if Path(document.filename).name == '03_Remediation_Action_Plan.pdf':
                captured.extend(
                    item.getPlainText() for item in flowables
                    if hasattr(item, 'getPlainText')
                )
            return original_build(document, flowables, *args, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            with patch.object(reporting.SimpleDocTemplate, 'build', record_build):
                zip_path = reporting.package(result, root=directory)
            pdf_path = Path(zip_path).with_suffix('') / '03_Remediation_Action_Plan.pdf'
            self.assertTrue(pdf_path.is_file(), 'Remediation PDF missing')
            self.assertTrue(pdf_path.read_bytes().startswith(b'%PDF-'))
            self.assertGreater(pdf_path.stat().st_size, 500)
        return '\n'.join(captured)

    def test_dmarc_raw_evidence_settings_and_recommendation(self):
        record = 'v=DMARC1; p=none; pct=25; rua=mailto:reports@nonprofit.example'
        content = self.generate([record], recommendation='Inventory senders and monitor DMARC reports.')
        for expected in (
            'Observed DMARC DNS Evidence', record,
            'Recognized records: 1', 'P: none', 'PCT: 25',
            'RUA: mailto:reports@nonprofit.example',
            'Severity: Medium', 'DMARC monitoring only.',
            'Inventory senders and monitor DMARC reports.',
            'Risk Explanation', 'monitoring-only',
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, content)

    def test_preparation_verification_rollback_and_approval(self):
        content = self.generate(['v=DMARC1; p=quarantine'])
        for expected in (
            'Implementation Preparation', 'legitimate email sending service',
            'Verification Procedure', 'authoritative DNS',
            'Rollback Procedure', 'original DNS record and TTL',
            'Change Ownership and Approval', 'designated decision-maker',
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, content)

    def test_other_email_controls_are_preserved(self):
        other = [
            {'control': 'SPF', 'severity': 'Medium',
             'observation': 'SPF has broad authorization.',
             'recommendation': 'Review authorized SPF senders.'},
            {'control': 'DKIM', 'severity': 'Low',
             'observation': 'Selector not supplied.',
             'recommendation': 'Confirm active DKIM selectors.'},
        ]
        content = self.generate(['v=DMARC1; p=none'], other_findings=other)
        for expected in (
            'SPF - Medium', 'SPF has broad authorization.',
            'Review authorized SPF senders.', 'DKIM - Low',
            'Selector not supplied.', 'Confirm active DKIM selectors.',
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, content)

    def test_missing_record_does_not_invent_dns_evidence(self):
        content = self.generate(
            [], severity='High', observation='No DMARC record found.',
            recommendation='Investigate DNS and publish a validated DMARC record.',
            status='no_answer',
        )
        self.assertIn('Recognized records: 0', content)
        self.assertIn('No DMARC TXT record returned.', content)
        self.assertIn('No recognized DMARC record was found', content)
        self.assertIn('Lookup status: no_answer', content)
        self.assertIn('Investigate DNS and publish a validated DMARC record.', content)
        self.assertNotIn('domain requests rejection', content)

    def test_invalid_high_severity_record_not_treated_as_enforced(self):
        content = self.generate(
            ['v=DMARC1; p=reject; pct=invalid'],
            severity='High', observation='Invalid pct value.',
            recommendation='Correct the malformed pct tag.',
        )
        self.assertIn('high-severity finding', content)
        self.assertIn('Correct the malformed pct tag.', content)
        self.assertNotIn('domain requests rejection', content)


if __name__ == '__main__':
    unittest.main()
