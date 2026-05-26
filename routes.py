from fastapi import APIRouter
from collections import Counter

from backend.scanners.scanner_service import run_scan
from backend.risk_engine.risk_calculator import calculate_risk
from backend.threat_intel.threat_service import get_threat_data
from backend.ai_engine.ai_service import analyze_vulnerability

router = APIRouter()


@router.get("/")
def home():
    return {
        "message": "Security Orchestrator Running"
    }


@router.get("/scan")
def scan():

    results = run_scan()

    final_results = []

    severity_counter = Counter()

    total_risk = 0

    for result in results:

        severity = result["severity"]

        risk_score = calculate_risk(
            severity
        )

        total_risk += risk_score

        severity_counter[
            severity.upper()
        ] += 1

        threat = get_threat_data(
            severity
        )

        ai_analysis = analyze_vulnerability(
            result["issue"]
        )

        final_results.append({
            "tool":
            result["tool"],

            "severity":
            severity,

            "issue":
            result["issue"],

            "file":
            result["file"],

            "risk_score":
            risk_score,

            "threat":
            threat[
                "threat_level"
            ],

            "ai_fix":
            ai_analysis[
                "fix"
            ]
        })

    return {
        "summary": {

            "total_findings":
            len(results),

            "critical":
            severity_counter[
                "CRITICAL"
            ],

            "high":
            severity_counter[
                "HIGH"
            ],

            "medium":
            severity_counter[
                "MEDIUM"
            ],

            "low":
            severity_counter[
                "LOW"
            ],

            "overall_risk_score":
            total_risk
        },

        "top_findings":
        final_results[:10]
    }