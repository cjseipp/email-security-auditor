# email-security-auditor
Cyber Ready Clinic project: A Windows-based tool for auditing nonprofit email authentication (SPF, DKIM, DMARC), identifying risks, and generating actionable security reports.


## Download Email Security Auditor

**Latest Windows release: v1.0.1**

[Download CyberReadyAudit.exe](https://github.com/cjseipp/email-security-auditor/releases/download/v1.0.1/CyberReadyAudit.exe)

### Installation and Use

1. Download `CyberReadyAudit.exe`.
2. Save it to a folder on your Windows computer.
3. Double-click the executable to launch the application.
4. Enter the domain you want to assess.
5. Confirm or change the optional DKIM selector.
6. Click **Run Assessment and Create Client Package**.
7. Review the SPF, DKIM, and DMARC results and generated reports.

**No Python installation is required** for the Windows executable.

The application performs read-only public DNS checks and does not modify domain configurations.

**Note:** The executable is not digitally signed. Windows may display a security warning. Download only from the official GitHub release and verify the published SHA-256 checksum.

For previous versions, visit the [Releases page](https://github.com/cjseipp/email-security-auditor/releases).
