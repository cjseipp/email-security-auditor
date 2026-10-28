# Email Security Auditor

**Cyber Ready Clinic Capstone Project**

A Windows-based email security assessment tool designed to help small businesses and nonprofit organizations evaluate their email authentication configurations, identify potential security weaknesses, and generate actionable reports.

The application performs read-only public DNS assessments of **SPF (Sender Policy Framework), DKIM (DomainKeys Identified Mail), and DMARC (Domain-based Message Authentication, Reporting, and Conformance)**.

## Application Screenshot

![Email Security Auditor desktop application](images/email-auditor-desktop.png)

## Download Email Security Auditor

**Latest Windows release: v1.0.1**

[**Download CyberReadyAudit.exe — Windows Application**](https://github.com/cjseipp/email-security-auditor/releases/download/v1.0.1/CyberReadyAudit.exe)

The Windows executable does not require a separate Python installation.

For earlier versions, visit the [GitHub Releases page](https://github.com/cjseipp/email-security-auditor/releases).

## Installation and Use

1. Download `CyberReadyAudit.exe` from the link above.
2. Save the executable to a folder on your Windows computer.
3. Double-click `CyberReadyAudit.exe` to launch the application.
4. Enter the domain you want to assess.
5. Confirm, change, or clear the optional DKIM selector (initially `default`).
6. Click **Run Assessment and Create Client Package**.
7. Review the SPF, DKIM, and DMARC findings and generated reports.

The application does not require administrative access to the domain or make changes to DNS records.

## Features

- SPF record discovery and assessment
- DKIM selector DNS lookup
- DMARC record and policy assessment
- Findings with recommended next steps
- Windows desktop graphical interface
- Streamlit browser-based interface for Python users
- Automated client report package generation
- Supporting technical evidence

## Client Report Package

Each completed assessment generates a ZIP package containing:

| File | Description |
|---|---|
| `01_Executive_Summary.pdf` | Management-level overview |
| `02_Email_Security_Dashboard.html` | Browser-based assessment dashboard |
| `03_Remediation_Action_Plan.pdf` | Recommended corrective actions |
| `04_Technical_Findings.xlsx` | Detailed technical findings |
| `05_Client_Instructions.pdf` | Guidance for interpreting the assessment |
| `Technical_Evidence/` | Supporting DNS evidence |

## Technical Architecture

Email Security Auditor is a Python-based cybersecurity assessment application with two user interfaces that share a common assessment engine and reporting system.

### Application Components

| Component | Technology | Function |
|---|---|---|
| Desktop Interface | Python Tkinter | Provides a Windows graphical interface for entering domains, running assessments, and generating reports. |
| Browser Interface | Streamlit | Provides a local web-based interface for performing the same assessments through a browser. |
| Assessment Engine | Python, dnspython | Queries public DNS records to evaluate SPF, DKIM, and DMARC configurations. |
| Reporting Engine | Python, ReportLab, HTML, Excel | Generates executive summaries, technical findings, remediation recommendations, and supporting evidence. |
| Windows Distribution | PyInstaller | Packages the desktop application into a standalone Windows executable. |

### Assessment Workflow

1. **User Input:** The user enters a domain name and optionally specifies a DKIM selector.
2. **DNS Discovery:** The assessment engine performs public DNS queries for SPF, DKIM, and DMARC records.
3. **Security Analysis:** Retrieved DNS information is evaluated to identify authentication configurations and potential security weaknesses.
4. **Findings and Recommendations:** The application prepares assessment results and suggested remediation actions.
5. **Report Generation:** The reporting engine produces PDF, HTML, Excel, and supporting technical evidence files.
6. **Client Package:** The generated files are collected into a downloadable ZIP archive.

### Source Code Organization

```text
email-security-auditor/
├── src/
│   ├── audit_engine.py
│   ├── desktop_app.py
│   ├── streamlit_app.py
│   └── reporting.py
├── tests/
│   └── test_audit.py
├── scripts/
│   ├── Install_Once.bat
│   ├── Start_Desktop.bat
│   ├── Start_Browser.bat
│   └── Build_Windows_EXE.bat
├── images/
├── requirements.txt
├── README.md
└── LICENSE
## Running from Source — Installation and Launch Guide

These instructions are intended for cybersecurity students, developers, and Cyber Ready Clinic participants who want to run the Python version of Email Security Auditor.

**Nontechnical users should download `CyberReadyAudit.exe` from the GitHub Releases page instead.** The standalone executable does not require Python or any batch files.

### Prerequisites

- Windows computer
- Python 3 installed, with the `py` launcher or `python` command available
- Internet connection

### Step 1 — Download the source code

1. Click the green **Code** button on this repository.
2. Select **Download ZIP**.
3. Extract the downloaded ZIP into a folder.
4. Open the extracted `email-security-auditor-main` folder.
5. Open the `scripts` folder.

### Step 2 — Install dependencies (first time only)

Double-click:

`Install_Once.bat`

This script creates a Python virtual environment (`.venv`) and installs the dependencies listed in `requirements.txt`.

Wait for the message **Setup complete** before proceeding.

### Step 3 — Choose your application interface

**Option A — Windows desktop application**

Double-click:

`Start_Desktop.bat`

The Email Security Auditor desktop window will open.

**Option B — Browser-based application**

Double-click:

`Start_Browser.bat`

The Streamlit application will start on your computer. Open `http://localhost:8501` in your browser if it does not open automatically.

You can use either interface; running both is not required.

### Step 4 — Perform an assessment

1. Enter the domain name.
2. Confirm or enter the optional DKIM selector.
3. Run the assessment.
4. Review the SPF, DKIM, and DMARC findings.
5. Locate the generated client report package.

For source installations, reports are generated in the `client_packages` folder at the project root.

### Step 5 — Build the Windows executable (optional)

To create a standalone Windows executable, double-click:

`Build_Windows_EXE.bat`

Run `Install_Once.bat` first if setup has not already been completed.

After a successful build, the executable is located at:

`dist\CyberReadyAudit.exe`

This build step is intended for developers preparing a Windows release. It is not necessary for ordinary assessments.

### Batch File Reference

| File | When to use |
|---|---|
| `Install_Once.bat` | First-time Python setup |
| `Start_Desktop.bat` | Launch the desktop interface |
| `Start_Browser.bat` | Launch the browser interface |
| `Build_Windows_EXE.bat` | Build a standalone Windows executable |

**Security note:** The application performs read-only public DNS queries. It does not change DNS records or require access to the organization's email administration system.

```
### Security Design

The application uses a read-only assessment approach:

- Queries publicly available DNS information.
- Does not require DNS administrator credentials.
- Does not modify email authentication records.
- Preserves supporting technical evidence for review.
- Separates assessment processing from the desktop and browser interfaces.

**Assessment limitation:** DNS configuration checks do not independently prove that email authentication succeeds for actual sent messages. Findings should be validated before implementing changes.

## Security and Limitations

- The application performs read-only public DNS checks.
- No DNS configurations are modified.
- A successful DKIM selector lookup does not prove that outgoing email is signed.
- DNS lookup failures should be verified before drawing security conclusions.
- Assessment findings should be reviewed before implementing remediation changes.
- The Windows executable is not digitally signed and may trigger a Windows security warning.

Download the executable only from the official GitHub release and compare its SHA-256 checksum with the value displayed in the release assets.

## Source Code

The repository contains the Python application source, tests, dependency requirements, and Windows installation and build scripts.

Developers can review the source code or build the application using the files provided in this repository.

## Project Purpose

Developed as a Cyber Ready Clinic capstone project, Email Security Auditor demonstrates practical application of cybersecurity assessment, email authentication analysis, risk identification, technical evidence collection, and client-focused reporting.

The project is intended to help organizations better understand their email security posture and identify opportunities for improvement.
