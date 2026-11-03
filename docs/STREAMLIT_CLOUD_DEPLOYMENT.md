# Streamlit Community Cloud — deployment guide

## Preparation

This cloud-preview branch uses the existing `src/audit_engine.py` and `src/reporting.py`, with an updated `src/streamlit_app.py`. It does not change the Windows desktop executable or batch files.

1. Upload these changed files to a new GitHub branch named `streamlit-cloud` (not `main`).
2. Go to https://share.streamlit.io/ and sign in using GitHub.
3. Choose **Create app** / **Deploy a public app from GitHub**.
4. Select repository `cjseipp/email-security-auditor`, branch `streamlit-cloud`, and entry point `src/streamlit_app.py`.
5. Select an available Python version compatible with the dependencies (3.11 is suitable).
6. Deploy and inspect the build logs if dependency installation fails.
7. Test an authorized domain, confirm the results, and download/open the ZIP.

## Security and operating limitations

**Keep access limited to trusted testers initially.** Streamlit Community Cloud access controls vary by deployment and plan. Do not assume that a public app is private. Authorization checkbox is a notice, not authentication.

- Each report is generated in an isolated temporary directory, read into the visitor's session, and the temporary directory is deleted after packaging.
- Streamlit session state holds the ZIP in server memory until the session ends. This is not a guarantee of secure deletion or a substitute for privacy controls.
- The application does not yet implement server-side per-IP rate limiting, authentication, a usage quota, or comprehensive abuse monitoring. **Do not publish unrestricted access until these controls are addressed or hosting access is restricted.**
- DNS queries are limited to names validated as DNS domains; this is not a general-purpose URL fetcher.
- The app's reports may contain public infrastructure information and should not be shared indiscriminately.
- No production DNS changes are made.
- The source-installation batch files are for Windows and do not run on Streamlit Cloud.

## Notes

The repository's root `requirements.txt` is used by Streamlit Cloud. PyInstaller is a desktop-build dependency and is not required by the hosted app, but retaining it here avoids altering the existing Windows developer workflow.

After successful testing, add the hosted URL to the README as an alternative to the Windows download.
