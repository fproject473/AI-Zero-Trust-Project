# AI-Zero-Trust-Project
Capstone project implementing an AI-driven Zero Trust Security Framework using machine learning and virtualized environments
AI-Enhanced Zero Trust Security Prototype Using Sysmon Logs
1. Project Overview
This project demonstrates how Zero Trust Architecture (ZTA) can be enhanced using machine learning to detect abnormal behavior on a Windows system.
Using Sysmon logs, I built a lightweight anomaly detection model (Isolation Forest) that identifies suspicious system events and assigns risk scores consistent with Zero Trust’s “never trust, always verify” principle.
This repository includes the scripts, data samples, documentation, and analysis needed to reproduce the project.
________________________________________
2. Project Relevance (Why This Matters)
Modern cyber threats often bypass traditional perimeter defenses.
Zero Trust requires continuous monitoring, but manually reviewing logs is nearly impossible.
This project matters because it shows how:
•	AI/ML can support Zero Trust by scoring system behavior in real time
•	Sysmon logs can act as a high-quality forensic and behavioral dataset
•	Analysts can automate threat detection using affordable tools
•	Students can learn practical skills used in SOC, IR, and DFIR roles
Skills developed:
•	Log forensics
•	Windows system monitoring
•	Machine learning for security
•	Zero Trust architecture
•	Building repeatable cybersecurity tooling
Who benefits:
•	SOC analysts
•	Incident responders
•	Cybersecurity students
•	Analysts designing Zero Trust pipelines
________________________________________
3. Methodology
3.1 Setup & Environment
Component	Details
OS	Windows 10 VM
Logging Tool	Sysmon v14 (SwiftOnSecurity config)
Data Export	Event Viewer → CSV
Analysis	Python (Pandas + Isolation Forest)
Storage	Google Drive + this GitHub repo
Sysmon Events used:
•	Event ID 1 – Process creation
•	Event ID 3 – Network connection
•	Event ID 7 – Image loaded
•	Event ID 11 – File creation
________________________________________
3.2 Tools Used
•	Sysmon for high-fidelity system monitoring
•	Python (pandas, scikit-learn)
•	draw.io for diagrams
•	VirtualBox/VMware Windows VM
•	Google Drive for dataset storage

 Architecture / Workflow Diagram

         | Windows VM (Sysmon) |
         +----------+----------+
                    |
                    | Sysmon Logs (XML/EVTX)
                    v
        +---------------------------+
        | Export as CSV (Event Log) |
        +-------------+-------------+
                      |
                      v
        +---------------------------+
        |   Data Cleaning Script    |
        |  (parse + feature build)  |
        +-------------+-------------+
                      |
                      v
        +---------------------------+
        | Isolation Forest ML Model |
        | -> Normal / High Risk     |
        +-------------+-------------+
                      |
                      v
        +---------------------------+
        |   Zero Trust Risk Score   |
        |  + Visualization/Reports  |
        +---------------------------+


