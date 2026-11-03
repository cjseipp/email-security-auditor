
import streamlit as st

st.set_page_config(page_title="Streamlit Diagnostic")

st.title("Streamlit Browser Compatibility Test")

domain = st.text_input("Domain to assess", "example.org")
selector = st.text_input("DKIM selector", "default")
authorized = st.checkbox("I am authorized to assess this domain.")

if st.button("Test Controls"):
    st.success("Streamlit controls are working.")
    st.write("Domain:", domain)
    st.write("Selector:", selector)
    st.write("Authorized:", authorized)

