🔍 VantaAudit: Static Malware Intelligence Engine
VantaAudit is a lightweight, high-performance static analysis tool designed to perform rapid triage on suspicious files. By combining local heuristic analysis with global threat intelligence, VantaAudit provides a "Vanta Threat Score" to help security researchers identify malicious payloads before execution.

🚀 Key Features
Masquerade Detection: Identifies executables disguised with non-threatening extensions (e.g., invoice.pdf.exe).

Shannon Entropy Analysis: Measures data randomness to detect the presence of packers, obfuscation, or encrypted ransomware payloads.

Global Intelligence Integration: Connects to the VirusTotal V3 API to cross-reference file hashes against over 70+ antivirus engines.

Heuristic Scoring System: Generates a 0-100 risk report based on multiple security vectors.

Secure API Handling: Built with professional security standards; uses Environment Variables to manage sensitive API keys.

🛠️ Technical Stack
Language: Java 23

Networking: OkHttp 3

Data Parsing: Google GSON

UI: Java Swing

Security: SHA-256 Hashing, Shannon Entropy Algorithms

🛡️ Security & Privacy
[!IMPORTANT]
This project does not contain hardcoded API keys. To use the global intelligence features, you must provide your own VirusTotal API key via environment variables.

Setup
Obtain an API key from VirusTotal.

Add the key to your system environment variables:

Variable Name: VANTA_API_KEY

Value: your_api_key_here

Restart your IDE/Terminal to load the variable.

📊 Analysis Logic
VantaAudit calculates the threat score based on:
| Check | Weight | Logic |
| :--- | :--- | :--- |
| Masquerading | 30 pts | Matches file headers against extensions. |
| High Entropy | 20 pts | Detects if the file is packed (Entropy > 7.0). |
| API Reputation | 50 pts | Scans global databases for known malicious signatures. |
