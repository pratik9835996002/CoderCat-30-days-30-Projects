from urllib.parse import urlparse

import requests
from flask import Flask, render_template, request


VIRUSTOTAL_API_KEY = "f9c7fdfb409683759765d6a8857afd3c82faf1f449e2448fff7234b8ece655b0"

VT_URL_SUBMIT_ENDPOINT = "https://www.virustotal.com/api/v3/urls"
VT_ANALYSIS_ENDPOINT = "https://www.virustotal.com/api/v3/analyses/{analysis_id}"

app = Flask(__name__)


def is_valid_url(url):
    parsed_url = urlparse(url)
    return parsed_url.scheme in {"http", "https"} and bool(parsed_url.netloc)


def get_verdict(stats):
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if malicious > 0:
        return "DANGEROUS", "danger"
    if suspicious > 0:
        return "SUSPICIOUS", "warning"
    return "SAFE", "safe"


def extract_categories(analysis_data):
    results = analysis_data.get("attributes", {}).get("results", {})
    categories = set()

    for engine_result in results.values():
        category = engine_result.get("category")
        result = engine_result.get("result")

        if category in {"malicious", "suspicious"} and result:
            categories.add(str(result).strip().lower())

    return sorted(categories)


def check_url_with_virustotal(url):
    headers = {
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded",
        "x-apikey": VIRUSTOTAL_API_KEY,
    }

    submit_response = requests.post(
        VT_URL_SUBMIT_ENDPOINT,
        headers=headers,
        data={"url": url},
        timeout=20,
    )
    submit_response.raise_for_status()

    analysis_id = submit_response.json()["data"]["id"]

    analysis_response = requests.get(
        VT_ANALYSIS_ENDPOINT.format(analysis_id=analysis_id),
        headers={"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY},
        timeout=20,
    )
    analysis_response.raise_for_status()

    analysis_data = analysis_response.json()["data"]
    attributes = analysis_data.get("attributes", {})
    stats = attributes.get("stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    total_engines = malicious + suspicious + harmless + undetected
    flagged_engines = malicious + suspicious

    malicious_ratio = round((flagged_engines / total_engines) * 100, 1) if total_engines else 0
    clean_ratio = max(0, 100 - malicious_ratio)

    verdict, verdict_class = get_verdict(stats)

    return {
        "url": url,
        "verdict": verdict,
        "verdict_class": verdict_class,
        "stats": stats,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "flagged_engines": flagged_engines,
        "total_engines": total_engines,
        "malicious_ratio": malicious_ratio,
        "clean_ratio": clean_ratio,
        "categories": extract_categories(analysis_data),
    }


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None
    submitted_url = ""

    if request.method == "POST":
        submitted_url = request.form.get("url", "").strip()

        if not submitted_url:
            error = "Please enter a URL to check."
        elif not is_valid_url(submitted_url):
            error = "Please enter a valid URL that starts with http:// or https://."
        elif VIRUSTOTAL_API_KEY == "your_key_here":
            error = "Add your VirusTotal API key at the top of app.py before checking URLs."
        else:
            try:
                result = check_url_with_virustotal(submitted_url)
            except requests.exceptions.HTTPError as exc:
                status_code = exc.response.status_code if exc.response else "unknown"
                error = f"VirusTotal returned an error while checking this URL. Status: {status_code}."
            except requests.exceptions.RequestException:
                error = "Could not reach VirusTotal. Please check your connection and try again."
            except (KeyError, ValueError):
                error = "VirusTotal returned an unexpected response. Please try again."

    return render_template(
        "index.html",
        result=result,
        error=error,
        submitted_url=submitted_url,
    )


if __name__ == "__main__":
    app.run(debug=True)