"""Garak external scanner wrapper. Requires `pip install garak`."""
import subprocess
import shlex


def run_garak(model_type, model_name, probes="all",
              report_path="garak_report.jsonl"):
    cmd = (f"python -m garak --model_type {shlex.quote(model_type)} "
           f"--model_name {shlex.quote(model_name)} "
           f"--probes {shlex.quote(probes)} "
           f"--report_prefix {shlex.quote(report_path)}")
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return proc.returncode, proc.stdout + "\n" + proc.stderr