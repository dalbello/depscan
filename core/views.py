import json
import re
import stripe
import tomllib
import urllib.error
import urllib.request
from collections import Counter
from packaging import version

from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_POST


def home(request):
    context = {
        "stripe_publishable_key": settings.STRIPE_PUBLISHABLE_KEY,
    }
    if request.user.is_authenticated and request.user.is_staff:
        context["staff_bypass"] = True
    return render(request, "home.html", context)


def _parse_dependencies(content: str, file_type: str):
    deps = []

    if file_type == "package.json":
        data = json.loads(content)
        for section in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
            for name, ver in data.get(section, {}).items():
                clean = re.sub(r"^[\^~><=\s]+", "", str(ver)).split("||")[0].strip()
                deps.append((name, clean or "0.0.0"))

    elif file_type == "requirements.txt":
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|>|<)?\s*([A-Za-z0-9_.\-]+)?", line)
            if m:
                deps.append((m.group(1), m.group(3) or "0.0.0"))

    elif file_type == "go.mod":
        in_require = False
        for line in content.splitlines():
            s = line.strip()
            if s.startswith("require ("):
                in_require = True
                continue
            if in_require and s == ")":
                in_require = False
                continue
            if s.startswith("require "):
                parts = s.split()
                if len(parts) >= 3:
                    deps.append((parts[1], parts[2].lstrip("v")))
            elif in_require and s:
                parts = s.split()
                if len(parts) >= 2:
                    deps.append((parts[0], parts[1].lstrip("v")))

    elif file_type == "Gemfile":
        for line in content.splitlines():
            m = re.search(r"gem\s+['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]", line)
            if m:
                deps.append((m.group(1), re.sub(r"^[~><=\s]+", "", m.group(2))))

    elif file_type == "composer.json":
        data = json.loads(content)
        for section in ["require", "require-dev"]:
            for name, ver in data.get(section, {}).items():
                clean = re.sub(r"^[\^~><=\s]+", "", str(ver)).split("|")[0].strip()
                deps.append((name, clean or "0.0.0"))

    elif file_type == "Cargo.toml":
        data = tomllib.loads(content)
        for section in ["dependencies", "dev-dependencies", "build-dependencies"]:
            for name, ver in data.get(section, {}).items():
                if isinstance(ver, str):
                    clean = re.sub(r"^[\^~><=\s]+", "", ver).strip()
                    deps.append((name, clean or "0.0.0"))
                elif isinstance(ver, dict):
                    clean = re.sub(r"^[\^~><=\s]+", "", str(ver.get("version", "0.0.0"))).strip()
                    deps.append((name, clean or "0.0.0"))

    elif file_type == "pom.xml":
        blocks = re.findall(r"<dependency>(.*?)</dependency>", content, flags=re.S)
        for block in blocks:
            aid = re.search(r"<artifactId>(.*?)</artifactId>", block)
            ver = re.search(r"<version>(.*?)</version>", block)
            if aid:
                deps.append((aid.group(1).strip(), ver.group(1).strip() if ver else "0.0.0"))

    uniq = []
    seen = set()
    for d in deps:
        key = (d[0].lower(), d[1])
        if key not in seen:
            seen.add(key)
            uniq.append(d)
    return uniq


def _osv_query(name: str, dep_version: str):
    payload = json.dumps({"package": {"name": name}, "version": dep_version}).encode("utf-8")
    req = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError:
        return {"vulns": []}


def _severity(v):
    sev = "UNKNOWN"
    score = 0.0
    for item in v.get("severity", []):
        if item.get("type") == "CVSS_V3":
            try:
                vector = item.get("score", "")
                m = re.search(r"CVSS:[0-9.]+/.*", vector)
                if m:
                    pass
                n = re.search(r"([0-9]+\.?[0-9]*)$", vector)
                if n:
                    score = float(n.group(1))
            except Exception:
                score = 0.0
    if score >= 9:
        sev = "CRITICAL"
    elif score >= 7:
        sev = "HIGH"
    elif score >= 4:
        sev = "MEDIUM"
    elif score > 0:
        sev = "LOW"
    return sev, score


def _safe_parse_ver(v: str):
    try:
        return version.parse(v)
    except Exception:
        return None


def _find_fixed_version(vuln):
    candidates = []
    for affected in vuln.get("affected", []):
        for r in affected.get("ranges", []):
            for e in r.get("events", []):
                if "fixed" in e:
                    candidates.append(e["fixed"])
    if not candidates:
        return "No fix published"
    parsed = [c for c in candidates if _safe_parse_ver(c) is not None]
    if not parsed:
        return candidates[0]
    return sorted(parsed, key=lambda x: _safe_parse_ver(x))[0]


def _ai_fix_suggestions(findings):
    if not settings.OPENAI_API_KEY or not findings:
        return []

    from openai import OpenAI

    client = OpenAI(api_key=settings.OPENAI_API_KEY)
    top = findings[:8]
    prompt = (
        "You are a senior AppSec engineer. Provide concise migration tips for these vulnerable dependencies. "
        "Return JSON array with fields package, advice, breaking_changes_watchouts."
        f"\n\nFindings: {json.dumps(top)}"
    )
    try:
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            temperature=0.2,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
        )
        content = resp.choices[0].message.content
        data = json.loads(content)
        return data.get("items", data.get("suggestions", [])) if isinstance(data, dict) else []
    except Exception:
        return []


@require_POST
def analyze(request):
    file_obj = request.FILES.get("dependency_file")
    file_type = request.POST.get("file_type", "")
    payment_intent_id = request.POST.get("payment_intent_id", "")

    if not file_obj:
        return JsonResponse({"error": "Upload a dependency file."}, status=400)

    content = file_obj.read().decode("utf-8", errors="ignore")
    if not file_type:
        file_type = file_obj.name.split("/")[-1]

    allowed = {"package.json", "requirements.txt", "go.mod", "Gemfile", "composer.json", "Cargo.toml", "pom.xml"}
    if file_type not in allowed:
        return JsonResponse({"error": "Unsupported file format."}, status=400)

    deps = _parse_dependencies(content, file_type)
    if not deps:
        return JsonResponse({"error": "No dependencies found in file."}, status=400)

    findings = []
    counts = Counter()
    for name, dep_version in deps[:120]:
        data = _osv_query(name, dep_version)
        for vuln in data.get("vulns", []):
            sev, score = _severity(vuln)
            counts[sev] += 1
            findings.append(
                {
                    "package": name,
                    "version": dep_version,
                    "id": vuln.get("id", "UNKNOWN"),
                    "summary": (vuln.get("summary") or "No summary")[:240],
                    "severity": sev,
                    "cvss": score,
                    "fixed_version": _find_fixed_version(vuln),
                }
            )

    findings.sort(key=lambda x: x["cvss"], reverse=True)
    score = max(0, 100 - (counts["CRITICAL"] * 25 + counts["HIGH"] * 12 + counts["MEDIUM"] * 5 + counts["LOW"] * 2))

    paid = False
    if request.user.is_authenticated and request.user.is_staff:
        paid = True
    elif payment_intent_id:
        stripe.api_key = settings.STRIPE_SECRET_KEY
        try:
            pi = stripe.PaymentIntent.retrieve(payment_intent_id)
            paid = pi and pi.get("status") == "succeeded"
        except Exception:
            paid = False

    response = {
        "status": "ok",
        "summary": {
            "dependencies_scanned": len(deps),
            "critical": counts["CRITICAL"],
            "high": counts["HIGH"],
            "medium": counts["MEDIUM"],
            "low": counts["LOW"],
            "security_score": score,
        },
        "top_findings": findings[:20],
    }

    if paid:
        response["ai_fix_suggestions"] = _ai_fix_suggestions(findings)
        response["full_report_unlocked"] = True
    else:
        response["full_report_unlocked"] = False
        response["upgrade_message"] = "Unlock AI migration suggestions and full report export for $1.99."

    return JsonResponse(response)


@require_POST
def create_payment_intent(request):
    stripe.api_key = settings.STRIPE_SECRET_KEY
    try:
        intent = stripe.PaymentIntent.create(
            amount=199,
            currency="usd",
            metadata={"product": "depscan_full_report"},
        )
        return JsonResponse({"clientSecret": intent.client_secret, "paymentIntentId": intent.id})
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)


def privacy(request):
    return render(request, "privacy.html")


def terms(request):
    return render(request, "terms.html")
