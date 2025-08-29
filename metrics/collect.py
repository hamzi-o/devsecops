import json
import time
import os
import argparse
from openai import OpenAI

metrics = {
    "scan_times": {},  # Time taken for each step (seconds)
    "failure_rates": {},  # 0=pass, 1=fail for each step
    "redteam_results": [],  # Results from redteam/run_attacks.py
    "explanations": {}  # OpenAI-generated explanations
}
start_times = {}

def explain_metrics(metrics, api_key, model="gpt-4o-mini"):
    if not api_key:
        return {
            "scan_times": "No API key provided",
            "failure_rates": "No API key provided",
            "redteam_results": "No API key provided"
        }
    client = OpenAI(api_key=api_key)
    prompt = f"""
    Explain the following pipeline metrics and red team results in a clear, concise manner for a cybersecurity report:

    Scan Times (seconds):
    {json.dumps(metrics['scan_times'], indent=2)}

    Failure Rates (0=pass, 1=fail):
    {json.dumps(metrics['failure_rates'], indent=2)}

    Red Team Results:
    {json.dumps(metrics['redteam_results'], indent=2)}

    For each metric and red team result, describe:
    - What it means
    - Its security implications
    - Recommended actions if issues are found
    Provide the response in three sections: 'Scan Times', 'Failure Rates', 'Red Team Results'.
    """
    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2
        )
        content = resp.choices[0].message.content
        # Split response into sections
        sections = {"scan_times": "", "failure_rates": "", "redteam_results": ""}
        current_section = None
        for line in content.splitlines():
            if line.startswith("Scan Times"):
                current_section = "scan_times"
            elif line.startswith("Failure Rates"):
                current_section = "failure_rates"
            elif line.startswith("Red Team Results"):
                current_section = "redteam_results"
            elif current_section:
                sections[current_section] += line + "\n"
        return {k: v.strip() for k, v in sections.items()}
    except Exception as e:
        return {
            "scan_times": f"Explanation unavailable: {str(e)}",
            "failure_rates": f"Explanation unavailable: {str(e)}",
            "redteam_results": f"Explanation unavailable: {str(e)}"
        }

def record_start(step):
    start_times[step] = time.time()

def record_end(step):
    if step in start_times:
        metrics["scan_times"][step] = round(time.time() - start_times[step], 2)
        metrics["failure_rates"][step] = metrics["failure_rates"].get(step, 0)

def record_failure(step, failed):
    metrics["failure_rates"][step] = 1 if failed else 0

def load_redteam_results(path):
    if os.path.exists(path):
        with open(path) as f:
            metrics["redteam_results"] = json.load(f)
    else:
        metrics["redteam_results"] = [{"error": "redteam_results.json not found"}]

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--step", help="Pipeline step (e.g., sast, redteam)")
    ap.add_argument("--start", action="store_true", help="Record start time")
    ap.add_argument("--end", action="store_true", help="Record end time")
    ap.add_argument("--failed", action="store_true", help="Mark step as failed")
    ap.add_argument("--finalize", action="store_true", help="Finalize metrics with explanations")
    ap.add_argument("--redteam", default="redteam_results.json", help="Path to redteam results")
    ap.add_argument("--out", default="metrics.json", help="Output file")
    ap.add_argument("--openai-api-key", default=os.getenv("OPENAI_API_KEY"), help="OpenAI API key")
    a = ap.parse_args()

    if a.step and a.start:
        record_start(a.step)
    elif a.step and a.end:
        record_end(a.step)
        if a.failed:
            record_failure(a.step, True)
    elif a.finalize:
        # Calculate gate failure rate
        if os.path.exists("enriched.jsonl"):
            findings = [json.loads(l) for l in open("enriched.jsonl")]
            metrics["failure_rates"]["gate"] = 1 if any(f["risk_score"] >= 0.70 for f in findings) else 0
        else:
            metrics["failure_rates"]["gate"] = 0
        # Load red team results
        load_redteam_results(a.redteam)
        # Generate explanations
        metrics["explanations"] = explain_metrics(metrics, a.openai_api_key)
        # Save metrics
        with open(a.out, "w") as f:
            json.dump(metrics, f, indent=2)
        print(f"Metrics saved: {a.out}")
