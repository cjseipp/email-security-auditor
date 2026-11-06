"""Regression tests for enhanced DMARC analysis. Run: python -m unittest discover -s tests -v"""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'src'))
from audit_engine import analyze_dmarc, audit


def response(*records, status='ok', error=None):
    result = {'status': status, 'values': [f'"{r}"' for r in records]}
    if error:
        result['error'] = error
    return result


class DMARCEnhancedTests(unittest.TestCase):
    def check(self, result, severity, observation_text, recommendation_text=None):
        self.assertEqual(severity, result[0])
        self.assertIn(observation_text, result[1])
        if recommendation_text:
            self.assertIn(recommendation_text, result[2])

    def test_missing_dmarc(self):
        self.check(analyze_dmarc(response(status='no_answer'), 'example.org'), 'High', 'No DMARC TXT record', 'monitoring policy')

    def test_monitoring_policy(self):
        self.check(analyze_dmarc(response('v=DMARC1; p=none; rua=mailto:reports@example.org'), 'example.org'), 'Review', 'Monitoring-only', 'alignment')

    def test_quarantine_policy(self):
        self.check(analyze_dmarc(response('v=DMARC1; p=quarantine; pct=25'), 'example.org'), 'Info', 'pct=25', 'aggregate reports')

    def test_reject_policy(self):
        self.check(analyze_dmarc(response('v=DMARC1; p=reject'), 'example.org'), 'Info', 'Reject enforcement', 'Monitor')

    def test_multiple_records(self):
        self.check(analyze_dmarc(response('v=DMARC1; p=none', 'v=DMARC1; p=reject'), 'example.org'), 'High', 'Multiple DMARC', 'Consolidate')

    def test_malformed_policy(self):
        self.check(analyze_dmarc(response('v=DMARC1; p=invalid'), 'example.org'), 'High', 'Validation errors', 'Correct')

    def test_duplicate_tags(self):
        self.check(analyze_dmarc(response('v=DMARC1; p=none; p=reject'), 'example.org'), 'High', 'duplicate tag p')

    def test_invalid_pct(self):
        self.check(analyze_dmarc(response('v=DMARC1; p=quarantine; pct=101'), 'example.org'), 'High', 'pct must be')

    def test_dns_failure_is_not_missing(self):
        self.check(analyze_dmarc(response(status='error', error='timeout'), 'example.org'), 'Unknown', 'timeout', 'Retry')

    def test_raw_evidence_and_findings_schema(self):
        class FakeResolver:
            def resolve(self, name, kind, lifetime=6):
                class Answer:
                    def __init__(self, value): self.value = value
                    def to_text(self): return self.value
                if name == '_dmarc.example.org' and kind == 'TXT':
                    return [Answer('"v=DMARC1; p=none; rua=mailto:reports@example.org"')]
                if name == 'example.org' and kind == 'TXT':
                    return [Answer('"v=spf1 -all"')]
                return [Answer('sample-record')]
        result = audit('example.org', resolver=FakeResolver())
        self.assertIn('raw_evidence', result)
        self.assertIn('DMARC', result['raw_evidence'])
        finding = next(x for x in result['findings'] if x['control'] == 'DMARC')
        self.assertEqual({'control', 'severity', 'observation', 'recommendation'}, set(finding))
        self.assertIn('v=DMARC1; p=none', finding['observation'])


if __name__ == '__main__':
    unittest.main()
