from pathlib import Path
from html import escape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter
import zipfile, json

def dmarc_report_data(result):
    """Separate observed DMARC DNS tags from protocol-derived defaults.

    Do not infer policy settings when DNS lookup fails, when no record is
    found, or when a single usable DMARC policy cannot be identified.
    """
    import re
    from audit_engine import txt_strings

    response = result.get('raw_evidence', {}).get('DMARC', {})
    status = str(response.get('status', 'not checked'))
    values = txt_strings(response.get('values', []))
    records = [
        value for value in values
        if re.match(r'^\s*v\s*=\s*DMARC1(?:\s*;|\s*$)', value, re.I)
    ]

    tags = {}
    if status.lower() == 'ok' and len(records) == 1:
        for part in records[0].split(';'):
            if '=' in part:
                key, value = part.split('=', 1)
                tags[key.strip().lower()] = value.strip()

    # A record must have exactly one recognized policy with a valid p tag
    # before interpreting omitted optional tags as protocol defaults.
    usable = (
        status.lower() == 'ok'
        and len(records) == 1
        and tags.get('p', '').lower() in ('none', 'quarantine', 'reject')
    )
    keys = ('p', 'sp', 'adkim', 'aspf', 'pct', 'rua', 'ruf', 'fo')
    if usable:
        defaults = {
            'p': 'Not specified (required tag)',
            'sp': tags['p'] + ' (inherited default; not published)',
            'adkim': 'r (relaxed; protocol default, not published)',
            'aspf': 'r (relaxed; protocol default, not published)',
            'pct': '100 (protocol default; not published)',
            'rua': 'Not specified in record',
            'ruf': 'Not specified in record',
            'fo': '0 (protocol default; not published)',
        }
        settings = {
            key: tags[key] + ' (published)' if key in tags else defaults[key]
            for key in keys
        }
    else:
        reason = (
            'Unable to determine (DNS lookup unsuccessful)'
            if status.lower() not in ('ok', 'nxdomain', 'noanswer', 'no_answer')
            else 'Not observed (no usable DMARC record retrieved)'
        )
        settings = {key: reason for key in keys}

    finding = next(
        (item for item in result.get('findings', [])
         if item.get('control') == 'DMARC'),
        {}
    )
    return {
        'status': status,
        'lookup_name': '_dmarc.' + result.get('domain', '').rstrip('.'),
        'raw_records': values,
        'record_count': len(records),
        'settings': settings,
        'usable_record': usable,
        'severity': finding.get('severity', 'Unknown'),
        'observation': finding.get('observation', ''),
        'recommendation': finding.get('recommendation', ''),
    }

def package(result,root='client_packages'):
    from audit_engine import save
    root=Path(root);root.mkdir(exist_ok=True,parents=True)
    folder=root/(result['domain'].replace('.','_')+'_'+result['scanned_utc'][:10].replace('-','')+'_'+result['scanned_utc'][11:19].replace(':',''))
    folder.mkdir(exist_ok=True)
    raw, csv=save(result,folder/'Technical_Evidence')
    findings=result['findings'];domain=result['domain']
    dmarc = dmarc_report_data(result)
    css='body{font:16px system-ui,Segoe UI,Arial;max-width:960px;margin:40px auto;padding:0 22px;color:#15243b;line-height:1.55}h1{color:#153d5b}article{border:1px solid #d6e1e8;border-radius:12px;padding:18px;margin:12px 0}.pill{display:inline-block;background:#eaf1f6;padding:3px 10px;border-radius:20px}small{color:#53657b}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccd8e1;padding:9px;text-align:left}'
    
    cards = ''.join(
        f'<article><h3>{escape(x["control"])} '
        f'<span class="pill">{escape(x["severity"])}</span></h3>'
        f'<p>{escape(x["observation"])}</p>'
        f'<p><b>Recommended action:</b> '
        f'{escape(x["recommendation"])}</p></article>'
        for x in findings
    )

    # Build DMARC analysis from actual DNS evidence.

    dmarc_rows = [
        ('DNS hostname queried', dmarc['lookup_name']),
        ('DNS lookup status', dmarc['status']),
        ('Recognized DMARC records', str(dmarc['record_count']))
    ]

    for key, value in dmarc['settings'].items():
        dmarc_rows.append((key.upper(), str(value)))

    dmarc_table = ''.join(
        '<tr><th scope="row">' + escape(label) +
        '</th><td>' + escape(value) + '</td></tr>'
        for label, value in dmarc_rows
    )

    raw_records = dmarc['raw_records']
    if raw_records:
        raw_html = ''.join(
            '<p><code style="overflow-wrap:anywhere">' +
            escape(record) + '</code></p>'
            for record in raw_records
        )
    else:
        raw_html = '<p>No TXT records returned.</p>'

    dmarc_html = (
        '<section>'
        '<h2>DMARC Configuration Analysis</h2>'
        '<p>Observed DNS evidence and interpreted policy settings.</p>'
        '<h3>Raw DMARC TXT Evidence</h3>'
        + raw_html +
        '<h3>Parsed DMARC Settings</h3>'
        '<table><tbody>' + dmarc_table + '</tbody></table>'
        '<h3>Assessment</h3>'
        '<p><b>Severity:</b> ' + escape(dmarc['severity']) + '</p>'
        '<p><b>Observation:</b> ' +
        escape(dmarc['observation']) + '</p>'
        '<p><b>Recommended action:</b> ' +
        escape(dmarc['recommendation']) + '</p>'
        '</section>'
    )

    html = (
        '<!doctype html><html lang="en"><head>'
        '<meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<title>Email security assessment - {escape(domain)}</title>'
        f'<style>{css}</style></head><body>'
        '<h1>Email Security Assessment</h1>'
        f'<p><b>Domain:</b> {escape(domain)}<br>'
        f'<b>Assessed (UTC):</b> {escape(result["scanned_utc"])}</p>'
        '<p class="pill">Preliminary read-only assessment '
        '- not a certification</p>'
        '<h2>What we checked</h2>'
        '<p>Public DNS records for email authentication and routing. '
        'This does not test actual mailbox security or prove '
        'that email spoofing was blocked.</p>'
        '<h2>Findings and next steps</h2>'
        + cards +
        dmarc_html +
        '<h2>Who should act?</h2>'
        '<p>Your designated IT provider or authorized DNS/email '
        'administrator should validate sending services, approve '
        'and implement any changes, and verify mail delivery.</p>'
        '<h2>Limits</h2>'
        f'<p>{escape(result["disclaimer"])}</p>'
        '<small>Cyber Ready Clinic capstone demonstration. '
        'Review findings with a qualified administrator before '
        'changing production email settings.</small>'
        '</body></html>'
    )

    (folder/'02_Email_Security_Dashboard.html').write_text(
        html, encoding='utf-8'
    )

    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name='NoteSmall',
            parent=styles['BodyText'],
            fontSize=9,
            leading=13,
            spaceAfter=9
        )
    )

    def pdf(filename, title, sections, compact=False, page_break_before=None):
        doc = SimpleDocTemplate(
            str(folder/filename),
            pagesize=(612, 792),
            leftMargin=48,
            rightMargin=48,
            topMargin=46,
            bottomMargin=46
        )

        # Executive Summary uses a tighter, readable one-page layout.
        # Other PDFs retain their original styles and spacing.
        if compact:
            heading_style = ParagraphStyle(
                'ExecutiveHeading', parent=styles['Heading2'],
                fontSize=10.5, leading=13, spaceBefore=3, spaceAfter=2,
                keepWithNext=True
            )
            body_style = ParagraphStyle(
                'ExecutiveBody', parent=styles['BodyText'],
                fontSize=9, leading=12
            )
            section_gap = 5
            title_gap = 5
        else:
            heading_style = styles['Heading2']
            body_style = styles['BodyText']
            section_gap = 10
            title_gap = 12

        story = [
            Paragraph(title, styles['Title']),
            Spacer(1, title_gap),
            Paragraph(
                'Domain: ' + escape(domain) +
                ' | UTC: ' + escape(result['scanned_utc']),
                styles['NoteSmall']
            ),
            Spacer(1, title_gap)
        ]

        for heading, body in sections:
            if page_break_before == heading:
                story.append(PageBreak())
                story.append(Paragraph(
                    'Remediation Action Plan - Implementation and Verification',
                    styles['Heading2']
                ))
                story.append(Spacer(1, 10))
            story.append(Paragraph(escape(heading), heading_style))
            story.append(Paragraph(escape(body), body_style))
            story.append(Spacer(1, section_gap))
        doc.build(story)
  
    # Evidence-based Executive Summary for nonprofit leadership.
    dmarc_policy = dmarc['settings'].get('p', 'Not observed')
    dmarc_pct = dmarc['settings'].get('pct', 'Not observed')
    dmarc_rua = dmarc['settings'].get('rua', 'Not observed')
    dmarc_severity = dmarc['severity']

    raw_dmarc = (
        ' | '.join(dmarc['raw_records'])
        if dmarc['raw_records']
        else 'No DMARC TXT record returned.'
    )

    if dmarc['status'].lower() == 'nxdomain':
        executive_risk = (
            'The DNS resolver returned NXDOMAIN for ' +
            dmarc['lookup_name'] + '. This is a valid negative DNS '
            'response indicating that the queried name was reported '
            'as nonexistent; it is not a timeout or connection failure. '
            'No published DMARC policy could be confirmed. Ask the '
            'authorized DNS administrator to check authoritative DNS '
            'and verify whether a DMARC record should be published.'
        )
    elif dmarc['status'].lower() not in ('ok', 'noanswer', 'no_answer'):
        executive_risk = (
            'The DMARC DNS lookup did not return a usable response '
            '(status: ' + dmarc['status'] + '). The domain policy '
            'cannot be confirmed from this assessment. Investigate '
            'the DNS lookup issue and repeat the assessment before '
            'deciding whether configuration changes are necessary.'
        )
    elif dmarc['record_count'] == 0:
        executive_risk = (
            'No recognized DMARC record was found in the returned DNS '
            'evidence. The organization should have its email '
            'administrator investigate and establish an appropriate '
            'DMARC policy.'
        )
    elif dmarc['record_count'] > 1:
        executive_risk = (
            'Multiple DMARC records were detected. This configuration '
            'can prevent reliable DMARC policy evaluation. The '
            'administrator should consolidate the records.'
        )
    elif dmarc_severity == 'High':
        executive_risk = (
            'The DMARC configuration has a high-severity finding. '
            'The published record may be invalid or contain conflicting '
            'settings. The authorized email administrator should review '
            'the raw DNS evidence and correct the configuration before '
            'relying on the published policy.'
        ) 
    elif dmarc['usable_record'] and dmarc_policy.startswith('none'):
        executive_risk = (
            'The domain publishes a monitoring-only DMARC policy '
            '(p=none). This does not request quarantine or rejection '
            'of messages that fail DMARC authentication. '
            'The organization should review authorized sending '
            'services and authentication reports before progressing '
            'toward enforcement.'
        )
    elif dmarc['usable_record'] and dmarc_policy.startswith('quarantine'):
        executive_risk = (
            'The domain requests quarantine of messages that fail '
            'DMARC authentication. The administrator should verify '
            'authorized senders, review aggregate reports, and '
            'confirm the enforcement percentage before considering '
            'a stronger policy.'
        )
    elif dmarc['usable_record'] and dmarc_policy.startswith('reject'):
        executive_risk = (
            'The domain requests rejection of messages that fail '
            'DMARC authentication. This is an enforcement policy, '
            'but public DNS evidence alone cannot establish '
            'whether all authorized messages authenticate correctly '
            'or how receivers handle them.'
        )
    else:
        executive_risk = (
            'The published DMARC policy requires administrator '
            'review. The recorded finding and technical evidence '
            'should be examined before changing DNS settings.'
        )

    other_findings = [
        item for item in findings
        if item['control'] != 'DMARC'
    ]

    other_summary = (
        ' | '.join(
            item['control'] + ': ' +
            item['severity'] + ' - ' +
            item['observation']
            for item in other_findings
        )
        if other_findings
        else 'No additional findings were reported.'
    )

    sections = [
        (
            'Assessment Scope',
            'Read-only examination of publicly available email-related '
            'DNS records for ' + domain + '. No mailbox access, '
            'test messages, or production configuration changes '
            'were performed.'
        ),
        (
            'Executive Risk Summary',
            executive_risk
        ),
        (
            'DMARC Finding Severity',
            dmarc_severity
        ),
        (
            'Observed DMARC Configuration',
            'Published policy (p): ' + dmarc_policy +
            ' | Enforcement percentage (pct): ' + dmarc_pct +
            ' | Aggregate reporting (rua): ' + dmarc_rua +
            ' | DNS hostname: ' + dmarc['lookup_name'] +
            ' | DNS lookup status: ' + dmarc['status']
        ),
        (
            'Raw DMARC DNS Evidence',
            raw_dmarc
        ),
        (
            'Assessment Interpretation',
            dmarc['observation'] or
            'No DMARC interpretation was provided.'
        ),
        (
            'Recommended Next Steps',
            dmarc['recommendation'] or
            'Ask the authorized email administrator to review '
            'the DNS evidence and determine appropriate next steps.'
        ),
        (
            'Other Email Security Findings',
            other_summary
        ),
        (
            'Responsibility',
            'The nonprofit executive director or designated owner '
            'should review the findings with the authorized IT '
            'provider or email administrator. Changes should be '
            'approved and tested before deployment.'
        ),
        (
            'Assessment Limitations',
            result['disclaimer']
        )
    ]

    pdf(
        '01_Executive_Summary.pdf',
        'Email Security - Executive Summary',
        sections,
        compact=True
    )

    
    # Evidence-based remediation action plan.
    plan = [
        (
            'Assessment Target',
            'Domain: ' + domain +
            ' | Assessment UTC: ' + result['scanned_utc']
        ),
        (
            '1. Observed DMARC DNS Evidence',
            'DNS hostname: ' + dmarc['lookup_name'] +
            ' | Lookup status: ' + str(dmarc['status']) +
            ' | Recognized records: ' + str(dmarc['record_count']) +
            ' | Raw TXT evidence: ' + raw_dmarc
        ),
        (
            '2. Parsed DMARC Configuration',
            ' | '.join(
                key.upper() + ': ' + str(value)
                for key, value in dmarc['settings'].items()
            )
        ),
        (
            '3. Identified DMARC Finding',
            'Severity: ' + dmarc['severity'] +
            ' | Observation: ' +
            (dmarc['observation'] or 'No observation provided.')
        ),
        (
            '4. Risk Explanation',
            executive_risk
        ),
        (
            '5. Recommended DMARC Remediation',
            dmarc['recommendation'] or
            'Review the DNS evidence with the authorized email '
            'administrator before deciding on changes.'
        ),
        (
            '6. Implementation Preparation',
            'Identify every legitimate email sending service. '
            'Confirm SPF and DKIM authentication and alignment. '
            'Review available DMARC aggregate reports. '
            'Record existing DNS values and TTLs. Obtain approval '
            'from the domain owner before modifying DNS.'
        ),
        (
            '7. Verification Procedure',
            'After an approved change, query the authoritative DNS '
            'records and confirm the intended DMARC policy is '
            'published. Send test messages through each authorized '
            'email service. Verify SPF, DKIM, and DMARC results '
            'in receiving message headers. Monitor aggregate '
            'reports and investigate authentication failures.'
        ),
        (
            '8. Rollback Procedure',
            'Preserve the original DNS record and TTL. '
            'If authorized mail delivery is disrupted, '
            'follow the approved rollback procedure to restore '
            'the previous known-working configuration. '
            'Allow for DNS caching and verify recovery.'
        )
    ]

    for item in findings:
        if item.get('control') != 'DMARC':
            plan.append((
                item['control'] + ' - ' + item['severity'],
                'Observed finding: ' + item['observation'] +
                ' | Recommended action: ' + item['recommendation']
            ))

    plan.append((
        '9. Change Ownership and Approval',
        'The authorized DNS or email administrator should '
        'implement approved changes. The nonprofit owner or '
        'designated decision-maker should authorize the work. '
        'Document the change, verification results, and '
        'any rollback actions.'
    ))

    pdf(
        '03_Remediation_Action_Plan.pdf',
        'Email Security - Remediation Action Plan',
        plan,
        page_break_before='6. Implementation Preparation'
    )

    pdf('05_Client_Instructions.pdf','How to Use Your Assessment',[('Open your dashboard','Double-click 02_Email_Security_Dashboard.html in File Explorer; it opens in Edge or Chrome. It is a saved report, not a live scan.'),('Read the summary','Open 01_Executive_Summary.pdf for the plain-language overview.'),('Who fixes problems?','Share 03_Remediation_Action_Plan.pdf and 04_Technical_Findings.xlsx with your IT provider. Do not change DNS records without authorization.'),('Reassess','Run the separate CyberReadyAudit.exe application if provided, click Run Assessment, and compare results. It needs internet access for public DNS lookups.'),('Privacy','Reports can reveal domain infrastructure. Share only with appropriate stakeholders.')])
    wb=Workbook()
    sheet=wb.active
    sheet.title='Findings'
    rows=[['Control','Severity','Observation','Recommendation']]+[[x[k] for k in ('control','severity','observation','recommendation')] for x in findings]
    for row in rows: sheet.append(row)
        
    dm_sheet = wb.create_sheet('DMARC Analysis')
    dm_sheet.append(['Setting', 'Observed value'])

    dm_sheet.append(['Domain', domain])
    dm_sheet.append(['DNS hostname queried', dmarc['lookup_name']])
    dm_sheet.append(['DNS lookup status', dmarc['status']])
    dm_sheet.append(['Recognized DMARC records', dmarc['record_count']])

    for record in dmarc['raw_records']:
        dm_sheet.append(['Raw TXT evidence', record])

    for key, value in dmarc['settings'].items():
        dm_sheet.append([key.upper(), value])

    dm_sheet.append(['Finding severity', dmarc['severity']])
    dm_sheet.append(['Observation', dmarc['observation']])
    dm_sheet.append(['Recommended action', dmarc['recommendation']])

    rawsheet=wb.create_sheet('Raw DNS')
    rawsheet.append(['Type','Lookup status','Record value'])
    for typ,v in result['raw_evidence'].items():
        for item in v['values'] or ['(no records returned)']:
            rawsheet.append([typ,v['status'],item])
    
    for ws,widths in [
        (sheet,[18,16,72,72]),
        (rawsheet,[18,22,95]),
        (dm_sheet,[26,100])
    ]:

        ws.freeze_panes='A2'
        ws.auto_filter.ref=ws.dimensions
        for i,width in enumerate(widths,1):ws.column_dimensions[get_column_letter(i)].width=width
        for cell in ws[1]:
            cell.fill=PatternFill('solid',fgColor='173B58')
            cell.font=Font(bold=True,color='FFFFFF')
        for row in ws.iter_rows(min_row=2):
            for cell in row:cell.alignment=Alignment(vertical='top',wrap_text=True)
    wb.save(folder/'04_Technical_Findings.xlsx')
    zpath=folder.with_suffix('.zip')
    with zipfile.ZipFile(zpath,'w',zipfile.ZIP_DEFLATED) as z:
        for p in folder.rglob('*'):
            if p.is_file():z.write(p,p.relative_to(folder))
    return zpath
