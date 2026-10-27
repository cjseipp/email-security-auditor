import streamlit as st
from audit_engine import audit
from reporting import package
st.set_page_config(page_title='Cyber Ready Email Auditor',page_icon='🛡️')
st.title('Email Security Reassessment')
st.caption('Read-only public DNS checks. No command-line skills required.')
domain=st.text_input('Domain','buktech.com')
selector=st.text_input('DKIM selector (optional)')
if st.button('Run Assessment',type='primary'):
    try:
        with st.spinner('Checking public DNS...'):
            result=audit(domain,dkim_selector=selector.strip())
            zipfile=package(result)
        st.success('Assessment complete')
        for f in result['findings']:
            with st.expander(f'{f["control"]} — {f["severity"]}',expanded=True):
                st.write(f['observation']);st.write('**Next step:**',f['recommendation'])
        with open(zipfile,'rb') as file:
            st.download_button('Download Client Report Package',file.read(),file_name=zipfile.name,mime='application/zip')
        with st.expander('Raw DNS evidence'):
            st.json(result['raw_evidence'])
    except Exception as e:st.error(str(e))
