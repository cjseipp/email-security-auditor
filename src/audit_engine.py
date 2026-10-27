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
    dmarc=[v for v in txt_strings(raw['DMARC']['values']) if v.lower().startswith('v=dmarc1')]
    if raw['DMARC']['status']=='ok':
        if not dmarc: add('DMARC','Review','No valid-looking DMARC version tag found.','Review published TXT record and DMARC syntax.')
        elif len(dmarc)>1: add('DMARC','High','Multiple DMARC records found.','Publish exactly one DMARC policy record.')
        else:
            policy=re.search(r'(?:^|;)\s*p\s*=\s*(none|quarantine|reject)(?:\s*;|\s*$)',dmarc[0],re.I)
            p=policy.group(1).lower() if policy else 'invalid/unknown'
            severity='Review' if p=='none' else ('Info' if p in ('reject','quarantine') else 'High')
            add('DMARC',severity,'Published DMARC policy p='+p+'; record: '+dmarc[0], 'Inventory legitimate senders, check alignment and aggregate reports before any enforcement change.' if p=='none' else 'Confirm SPF/DKIM alignment with real headers and monitor reports.')
    else: add('DMARC','Unknown','DMARC lookup returned '+raw['DMARC']['status'],'Confirm authoritative DNS and repeat lookup before drawing conclusions.')
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
