
import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from openpyxl import load_workbook
from reporting import package


class DMARCReportingTests(unittest.TestCase):

    def test_excel_dmarc_analysis(self):
        record = (
            "v=DMARC1; p=none; pct=50; "
            "rua=mailto:reports@example.org; "
            "adkim=s; aspf=r"
        )

        result = {
            "domain": "example.org",
            "scanned_utc": "2026-11-06T12:00:00+00:00",
            "raw_evidence": {
                "DMARC": {
                    "status": "ok",
                    "values": ['"' + record + '"']
                }
            },
            "findings": [
                {
                    "control": "DMARC",
                    "severity": "Review",
                    "observation": "Monitoring-only DMARC policy.",
                    "recommendation": (
                        "Review aggregate reports and verify "
                        "authorized senders before enforcement."
                    )
                }
            ],
            "disclaimer": "Automated preliminary assessment."
        }

        with tempfile.TemporaryDirectory() as temp:
            zip_path = package(result, root=temp)

            self.assertTrue(Path(zip_path).exists())

            with zipfile.ZipFile(zip_path) as archive:
                filename = "04_Technical_Findings.xlsx"
                self.assertIn(filename, archive.namelist())

                workbook_bytes = archive.read(filename)

            workbook = load_workbook(
                io.BytesIO(workbook_bytes),
                read_only=True
            )

            try:
                self.assertIn(
                    "DMARC Analysis",
                    workbook.sheetnames
                )

                sheet = workbook["DMARC Analysis"]

                data = {}
                for row in sheet.iter_rows(
                    min_row=2,
                    values_only=True
                ):
                    if row[0] is not None:
                        data[row[0]] = row[1]

                self.assertEqual(data["Domain"], "example.org")
                self.assertEqual(data["DNS lookup status"], "ok")
                self.assertEqual(data["Recognized DMARC records"], 1)

                self.assertEqual(data["Raw TXT evidence"], record)
                self.assertEqual(data["P"], "none")
                self.assertEqual(data["PCT"], "50")
                self.assertEqual(data["ADKIM"], "s")
                self.assertEqual(data["ASPF"], "r")
                self.assertEqual(
                    data["RUA"],
                    "mailto:reports@example.org"
                )

                self.assertEqual(
                    data["Finding severity"],
                    "Review"
                )

                self.assertIn(
                    "Review aggregate reports",
                    data["Recommended action"]
                )

            finally:
                workbook.close()


if __name__ == "__main__":
    unittest.main()
