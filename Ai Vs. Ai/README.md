**AI vs AI (Pentest App)**

**Installation & Usage Guide**

**Prerequisites**

Windows 10/11 (workson macOS/Linux too with shell adjustments)

Python 3.11+ — download from python.org. During install, check "Add Python to PATH".

At least one LLM API key (Anthropic, OpenAI, or compatible). For autonomous mode you'll want two (target + attacker) — three is best (+ judge).

***Step-by-Step Install***

***Download the zipped folder***

Download: [pentest-app.zip](https://github.com/nu11by73/Ag-RedPen/raw/refs/heads/main/pentest-app.zip)

Unzip the folder and make sure you see all the files below. 

(app.py, connectors.py, mutations.py, judge.py, runner.py, conversation.py, autonomous.py, knowledge.py, pyrit_integration.py, garak_integration.py, requirements.txt, setup.ps1, run.ps1).

***Allow PowerShell scripts (one-time)***

Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

***Run setup***

*powershell*

.\setup.ps1

This creates the venv, installs dependencies, and optionally installs garak/PyRIT.


***Launch the app***

*powershell*

.\run.ps1

Browser opens at http://localhost:8501.
