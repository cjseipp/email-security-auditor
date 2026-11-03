"""Hosted Streamlit interface. Reports are generated in an isolated temporary folder."""
from pathlib import Path
from tempfile import TemporaryDirectory
import re
import streamlit as st
from audit_engine import audit
from reporting import package

st.set_page_config(page_title="Email Security Auditor", page_icon="🛡️")
st.title("Email Security Auditor")
st.caption("Cyber Ready Clinic capstone | Preliminary, read-only public DNS assessment")
st.info("This demonstration checks public DNS records only. It does not access mailboxes, send messages, or modify DNS. Do not submit confidential information.")

if "assessment" not in st.session_state:
    st.session_state.assessment = None
if "report_bytes" not in st.session_state:
    st.session_state.report_bytes = None
if "report_name" not in st.session_state:
    st.session_state.report_name = None

with st.form("assessment_form"):
    domain = st.text_input("Domain to assess", placeholder="example.org", max_chars=253)
    selector = st.text_input("DKIM selector (optional)", value="default", max_chars=63)
    consent = st.checkbox("I understand this is a public-DNS demonstration and I am authorized to assess this domain.")
    submitted = st.form_submit_button("Run Assessment", type="primary")

if submitted:
    st.session_state.assessment = None
    st.session_state.report_bytes = None
    st.session_state.report_name = None
    normalized = domain.strip().lower().rstrip(".")
    if not consent:
        st.error("Please confirm authorization before proceeding.")
    elif not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", normalized):
        st.error("Enter a valid public DNS domain, such as example.org.")
    elif selector.strip() and not re.fullmatch(r"[A-Za-z0-9_-]{1,63}", selector.strip()):
        st.error("Enter a valid DKIM selector, or leave it blank.")
    else:
        try:
            with st.spinner("Checking public DNS records and preparing the report..."):
                result = audit(normalized, dkim_selector=selector.strip())
                # Each run gets a unique temporary directory; no client files remain in a shared folder.
                with TemporaryDirectory(prefix="email_audit_") as tmp:
                    archive = package(result, root=Path(tmp) / "client_packages")
                    data = archive.read_bytes()
                if len(data) > 20 * 1024 * 1024:
                    raise ValueError("Report package exceeds the 20 MB download limit.")
                st.session_state.assessment = result
                st.session_state.report_bytes = data
                st.session_state.report_name = archive.name
            st.success("Assessment complete. Download your report package below.")
        except Exception:
            st.error("The assessment could not be completed. Please verify the domain and try again.")

if st.session_state.assessment is not None:
    result = st.session_state.assessment
    st.subheader(f"Findings for {result['domain']}")
    for finding in result["findings"]:
        with st.expander(f"{finding['control']} — {finding['severity']}", expanded=True):
            st.write(finding["observation"])
            st.write("**Recommended next step:**", finding["recommendation"])
    st.download_button(
        "Download Client Report Package (ZIP)",
        data=st.session_state.report_bytes,
        file_name=st.session_state.report_name,
        mime="application/zip",
        type="primary",
    )
    with st.expander("Raw public DNS evidence"):
        st.json(result["raw_evidence"])
    st.caption("A DKIM DNS lookup does not prove that outgoing email is signed. Verify actual message authentication before changing production policies.")
