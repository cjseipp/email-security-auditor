
import tempfile
import unittest
from pathlib import Path

from reporting import package


class DMARCHTMLTests(unittest.TestCase):

    def test_html_dashboard_contains_dmarc_evidence(self):
        """Verify that generated HTML contains real DMARC evidence."""

        record = (
            'v=DMARC1; p=none; pct=50; '
            'rua=mailto:reports@example.org; adkim=s; aspf=r'
        )

        result = {
            'domain': 'example.org',
            'scanned_utc': '2026-11-06T12:00:00+00:00',
            'scope': 'Public DNS only.',
            'disclaimer': 'Preliminary automated assessment.',
            'raw_evidence': {
                'DMARC': {
                    'status': 'ok',
                    'values': ['"' + record + '"']
                }
            },
            'findings': [
                {
                    'control': 'DMARC',
                    'severity': 'Review',
                    'observation': (
                        'Monitoring-only DMARC policy detected.'
                    ),
                    'recommendation': (
                        'Review aggregate reports before '
                        'increasing enforcement.'
                    )
                }
            ]
        }

        with tempfile.TemporaryDirectory() as temp_dir:

            package(result, root=temp_dir)

            dashboards = list(
                Path(temp_dir).rglob(
                    '02_Email_Security_Dashboard.html'
                )
            )

            self.assertEqual(len(dashboards), 1)

            html = dashboards[0].read_text(
                encoding='utf-8'
            )

            # Confirm the new DMARC section exists.
            self.assertIn(
                'DMARC Configuration Analysis', html
            )

            # Confirm the raw DNS record is preserved.
            self.assertIn(record, html)

            # Confirm parsed configuration values.
            self.assertIn('DMARC1', html)
            self.assertIn('PCT', html)
            self.assertIn('50', html)
            self.assertIn('ADKIM', html)
            self.assertIn('ASPF', html)
            self.assertIn('mailto:reports@example.org', html)

            # Confirm evidence-based recommendations.
            self.assertIn(
                'Review aggregate reports before '
                'increasing enforcement.',
                html
            )

            # Confirm the report identifies its domain.
            self.assertIn('example.org', html)


if __name__ == '__main__':
    unittest.main()
