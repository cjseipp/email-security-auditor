import csv, json, re, datetime, pathlib
import dns.resolver

TYPES=('NS','SOA','MX','TXT')
def lookup(name,kind,resolver=None):
    resolver=resolver or dns.resolver.Resolver()
    try:
        answers=resolver.resolve(name,kind,lifetime=6)
        return {'status':'ok','values':[a.to_text() for a in answers]}
    except dns.resolver.NXDOMAIN: return {'status':'nxdomain','values':[]}
    except dns.resolver.NoAnswer: return {'status':'no_answer','values':[]}
    except (dns.exception.DNSException, OSError) as e: return {'status':'error','values':[],'error':str(e)}

def txt_strings(records):
    # dnspython text presentation has quoted chunks, possibly split across strings
    result=[]
    for value in records:
        chunks=re.findall(r'"([^"]*)"',value)
        result.append(''.join(chunks) if chunks else value)
    return result

def analyze_dmarc(response, domain):
    """Return one evidence-based finding without changing the existing report schema."""
    status = response.get('status', 'error')
    values = txt_strings(response.get('values', []))
    if status not in ('ok', 'no_answer', 'nxdomain'):
        return ('Unknown', f'DMARC DNS query returned {status}: {response.get("error", "no details")}',
                'Retry the query and verify authoritative DNS before concluding that DMARC is missing.')
    if status in ('no_answer', 'nxdomain'):
        return ('High', f'No DMARC TXT record was returned for _dmarc.{domain} (DNS status: {status}).',
                'Confirm authoritative DNS and publish one DMARC monitoring policy after choosing a monitored aggregate-report destination. Example only: v=DMARC1; p=none; rua=mailto:YOUR-VERIFIED-REPORT-ADDRESS;')
    candidates = [v for v in values if re.match(r'^\s*v\s*=\s*DMARC1(?:\s*;|\s*$)', v, re.I)]
    if len(candidates) > 1:
        return ('High', 'Multiple DMARC policy TXT records found: ' + ' | '.join(candidates),
                'Consolidate into exactly one valid DMARC TXT record; preserve intended policy and reporting tags.')
    if not candidates:
        return ('High', f'TXT lookup succeeded at _dmarc.{domain}, but no DMARC1 policy record was recognized. TXT values: {values!r}',
                'Inspect the TXT values for a malformed DMARC version tag; correct or add one valid DMARC policy record after DNS administrator review.')
    record = candidates[0]
    parts = [x.strip() for x in record.split(';') if x.strip()]
    tags = {}
    errors = []
    for part in parts:
        if '=' not in part:
            errors.append(f'malformed tag {part!r}')
            continue
        key, val = (x.strip() for x in part.split('=', 1))
        key = key.lower()
        if not re.fullmatch(r'[a-z]+', key): errors.append(f'invalid tag name {key!r}')
        if key in tags: errors.append(f'duplicate tag {key}')
        tags[key] = val
    if not parts or not re.fullmatch(r'v\s*=\s*DMARC1', parts[0], re.I):
        errors.append('v=DMARC1 must be first')
    if len(parts) < 2 or not re.match(r'^p\s*=', parts[1], re.I):
        errors.append('p= policy must be second')
    policy = tags.get('p', '').lower()
    if policy not in ('none', 'quarantine', 'reject'): errors.append('p must be none, quarantine or reject')
    if 'pct' in tags and (not tags['pct'].isdigit() or not 0 <= int(tags['pct']) <= 100):
        errors.append('pct must be an integer from 0 to 100')
    for key in ('adkim', 'aspf'):
        if key in tags and tags[key].lower() not in ('r', 's'): errors.append(f'{key} must be r or s')
    if 'sp' in tags and tags['sp'].lower() not in ('none', 'quarantine', 'reject'):
        errors.append('sp must be none, quarantine or reject')
    details = (f'Observed DMARC TXT: {record} | Parsed: p={policy or "missing"}, '
               f'pct={tags.get("pct", "100 (default)")}, rua={tags.get("rua", "not configured")}, '
               f'adkim={tags.get("adkim", "r (default)")}, aspf={tags.get("aspf", "r (default)")}, '
               f'sp={tags.get("sp", "inherits p")}.')
    if errors:
        return ('High', details + ' Validation errors: ' + '; '.join(errors),
                'Correct the listed syntax or policy errors in the existing TXT record; preserve valid reporting endpoints and other tags. Requery DNS after the change.')
    if policy == 'none':
        return ('Review', details + ' Monitoring-only policy does not request DMARC enforcement.',
                'Identify authorized senders; review aggregate reports and SPF/DKIM alignment; then plan a controlled move to quarantine or reject. Do not change enforcement solely from this DNS lookup.')
    if policy == 'quarantine':
        return ('Info', details + ' Quarantine enforcement requested for DMARC-failing mail, subject to receiver handling and pct.',
                'Review aggregate reports, alignment, subdomain policy and delivery impact before considering reject enforcement.')
    return ('Info', details + ' Reject enforcement requested for DMARC-failing mail, subject to receiver handling and pct.',
            'Monitor aggregate reports, verify legitimate sender alignment, and review pct/subdomain policy and delivery impact.')

def audit(domain,resolver=None,dkim_selector=''):
    domain=domain.strip().lower().rstrip('.')
    if not re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}',domain):
        raise ValueError('Enter a valid DNS domain, such as example.org')
    raw={kind:lookup(domain,kind,resolver) for kind in TYPES}
    raw['DMARC']=lookup('_dmarc.'+domain,'TXT',resolver)
    if dkim_selector:
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,63}',dkim_selector): raise ValueError('Invalid DKIM selector')
        raw['DKIM']=lookup(dkim_selector+'._domainkey.'+domain,'TXT',resolver)
    findings=[]
    def add(control,severity,observation,recommendation):
        findings.append(dict(control=control,severity=severity,observation=observation,recommendation=recommendation))
    spf=[v for v in txt_strings(raw['TXT']['values']) if v.lower().startswith('v=spf1')]
    if raw['TXT']['status']=='ok':
        if not spf: add('SPF','Review','No SPF record found in apex TXT records.','Confirm all sending platforms, then publish one correct SPF record.')
        elif len(spf)>1: add('SPF','High','Multiple SPF records found; SPF evaluation can fail.','Consolidate into one authorized SPF record.')
        else:
            add('SPF','Info','One SPF record published: '+spf[0],'Validate authorized senders and the 10-lookup limit; DNS presence does not prove delivery authentication.')
    else: add('SPF','Unknown','TXT lookup returned '+raw['TXT']['status'],'Repeat lookup; do not treat a DNS error as an absent record.')
    dmarc_severity, dmarc_observation, dmarc_recommendation = analyze_dmarc(raw['DMARC'], domain)
    add('DMARC', dmarc_severity, dmarc_observation, dmarc_recommendation)
    if dkim_selector:
        status=raw['DKIM']['status']
        add('DKIM','Info' if status=='ok' else 'Unknown','Selector '+dkim_selector+' lookup: '+status,'Verify a signed message header; selector lookup alone does not prove signing.')
    else: add('DKIM','Unknown','No selector supplied; DKIM cannot be assessed from arbitrary DNS guesses.','Obtain selector from a legitimate email header or email administrator.')
    return {'domain':domain,'scanned_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'raw_evidence':raw,'findings':findings,'scope':'Public DNS only; no email headers, message delivery, or DNS modifications.','disclaimer':'Automated preliminary findings require auditor review; DNS presence is not proof of operational effectiveness.'}

def save(result,base='reports'):
    path=pathlib.Path(base);path.mkdir(parents=True,exist_ok=True)
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M%S_%f')
    stem=result['domain'].replace('.','_')+'_'+stamp
    j=path/(stem+'.json');c=path/(stem+'.csv')
    j.write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding='utf-8')
    with c.open('w',newline='',encoding='utf-8-sig') as f:
        writer=csv.DictWriter(f,fieldnames=['control','severity','observation','recommendation']);writer.writeheader();writer.writerows(result['findings'])
    return j,c
