import subprocess
import json
import os


def run_bandit_scan():

    output_file = "bandit-results.json"

    subprocess.run([
        "python",
        "-m",
        "bandit",
        "-r",
        ".",
        "-f",
        "json",
        "-o",
        output_file
    ])

    findings = []

    if os.path.exists(output_file):

        with open(output_file, "r") as f:
            data = json.load(f)

        for item in data.get("results", []):

            findings.append({
                "tool": "Bandit",
                "severity": item.get(
                    "issue_severity",
                    "LOW"
                ),
                "issue": item.get(
                    "issue_text",
                    "Unknown issue"
                ),
                "file": item.get(
                    "filename"
                )
            })

    return findings


def run_semgrep_scan():

    output_file = "semgrep-results.json"

    subprocess.run([
        "python",
        "-m",
        "semgrep",
        "scan",
        "--config=auto",
        "--json",
        "--output",
        output_file
    ])

    findings = []

    if os.path.exists(output_file):

        with open(output_file, "r") as f:
            data = json.load(f)

        for item in data.get("results", []):

            findings.append({
                "tool": "Semgrep",
                "severity":
                item.get(
                    "extra",
                    {}
                ).get(
                    "severity",
                    "MEDIUM"
                ),

                "issue":
                item.get(
                    "extra",
                    {}
                ).get(
                    "message",
                    "Unknown issue"
                ),

                "file":
                item.get("path")
            })

    return findings


def run_dependency_scan():

    output_file = "dependency-results.json"

    subprocess.run([
        "python",
        "-m",
        "pip_audit",
        "-f",
        "json",
        "-o",
        output_file
    ])

    findings = []

    if os.path.exists(output_file):

        with open(output_file, "r") as f:
            data = json.load(f)

        for dep in data.get(
            "dependencies",
            []
        ):

            for vuln in dep.get(
                "vulns",
                []
            ):

                findings.append({
                    "tool": "pip-audit",
                    "severity": "HIGH",
                    "issue":
                    vuln.get(
                        "id",
                        "Dependency vulnerability"
                    ),
                    "file":
                    dep.get("name")
                })

    return findings


def run_scan():

    results = []

    results.extend(
        run_bandit_scan()
    )

    results.extend(
        run_semgrep_scan()
    )

    results.extend(
        run_dependency_scan()
    )

    return results