import subprocess


def run_diagnostic(host: str):
    # INTENTIONALLY VULNERABLE:
    # User-controlled input is inserted into a shell command.
    command = "nslookup " + host

    return subprocess.run(
        command,
        shell=True,
        check=True,
        capture_output=True,
        text=True,
    )