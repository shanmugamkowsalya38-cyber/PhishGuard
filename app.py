import streamlit as st
from urllib.parse import urlparse
from difflib import SequenceMatcher
import pandas as pd
import sqlite3
import socket
import ssl
import ipaddress
import re
import math
from datetime import datetime
from pathlib import Path

# Optional ML model. The app still works if the model is unavailable.
try:
    import joblib
except Exception:
    joblib = None

MODEL_FILE = "phishguard_model.pkl"
DB_FILE = "phishguard.db"

# These 5 features remain compatible with the existing Random Forest model.
MODEL_FEATURES = [
    "url_length",
    "has_https",
    "num_dots",
    "num_special_chars",
    "has_suspicious_keyword",
]

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "update",
    "secure", "account", "bank", "confirm", "password",
    "wallet", "payment", "invoice", "reset", "unlock"
]

SUSPICIOUS_TLDS = {
    "zip", "mov", "click", "top", "xyz", "work",
    "gq", "tk", "ml", "ga", "cf"
}

KNOWN_BRANDS = [
    "google", "paypal", "amazon", "microsoft", "apple",
    "facebook", "instagram", "netflix", "linkedin",
    "whatsapp", "adobe", "sbi", "hdfc", "icici"
]

CHAR_MAP = str.maketrans({
    "1": "l", "0": "o", "3": "e",
    "5": "s", "7": "t", "8": "b"
})


def load_model():
    if joblib is None or not Path(MODEL_FILE).exists():
        return None
    try:
        return joblib.load(MODEL_FILE)
    except Exception:
        return None


model = load_model()


def create_database():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            domain TEXT,
            risk_score INTEGER,
            result TEXT,
            impersonation TEXT,
            similarity INTEGER,
            scan_time TEXT
        )
    """)
    conn.commit()
    conn.close()


def save_scan(url, domain, risk_score, result, impersonation, similarity):
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        INSERT INTO scan_history
        (url, domain, risk_score, result,
         impersonation, similarity, scan_time)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        url, domain, risk_score, result,
        impersonation, similarity,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    conn.close()


def normalize_url(raw):
    """Validate URL syntax without contacting the website."""
    value = raw.strip()

    if not value:
        return None, None, ["No URL was entered."]

    if any(ch.isspace() for ch in value):
        return None, None, ["URL contains spaces."]

    # Allows both https://example.com and bare domains.
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "https://" + value

    try:
        parsed = urlparse(value)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        parsed.port  # Force validation of a malformed port.
    except ValueError:
        return None, None, ["Invalid URL syntax or port."]

    errors = []

    if scheme not in {"http", "https"}:
        errors.append("Only HTTP and HTTPS URLs are supported.")

    if not hostname:
        errors.append("A valid domain or host is required.")

    if hostname:
        try:
            ascii_host = hostname.encode("idna").decode("ascii").lower()
        except UnicodeError:
            errors.append("Domain contains invalid international characters.")
            ascii_host = hostname.lower()

        if len(ascii_host) > 253:
            errors.append("Domain name is too long.")
        if ".." in ascii_host:
            errors.append("Domain contains consecutive dots.")

    if errors:
        return None, None, errors

    return value, parsed, []


def host_parts(hostname):
    return [x for x in hostname.lower().rstrip(".").split(".") if x]


def get_base_domain(hostname):
    labels = host_parts(hostname)
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return hostname.lower().rstrip(".")


def shannon_entropy(text):
    if not text:
        return 0.0

    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1

    n = len(text)
    return -sum(
        (count / n) * math.log2(count / n)
        for count in counts.values()
    )


def extract_features(full_url, parsed):
    host = parsed.hostname or ""
    lower = full_url.lower()
    labels = host_parts(host)
    tld = labels[-1] if labels else ""

    found_keywords = sorted({
        word for word in SUSPICIOUS_KEYWORDS
        if word in lower
    })

    try:
        ipaddress.ip_address(host)
        is_ip_host = 1
    except ValueError:
        is_ip_host = 0

    digit_count = sum(ch.isdigit() for ch in host)

    return {
        # Existing Random Forest features
        "url_length": len(full_url),
        "has_https": int(parsed.scheme.lower() == "https"),
        "num_dots": full_url.count("."),
        "num_special_chars": sum(
            full_url.count(c) for c in ["@", "-", "_"]
        ),
        "has_suspicious_keyword": int(bool(found_keywords)),

        # Additional evidence features
        "hostname_length": len(host),
        "subdomain_count": max(0, len(labels) - 2),
        "hyphen_count": host.count("-"),
        "digit_count": digit_count,
        "digit_ratio": round(
            digit_count / max(1, len(host)), 3
        ),
        "has_ip_host": is_ip_host,
        "has_at_symbol": int("@" in parsed.netloc),
        "has_punycode": int(
            any(label.startswith("xn--") for label in labels)
        ),
        "suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "path_length": len(parsed.path or ""),
        "query_length": len(parsed.query or ""),
        "hostname_entropy": round(
            shannon_entropy(host), 3
        ),
        "found_keywords": found_keywords,
        "base_domain": get_base_domain(host),
    }


def normalized_token(text):
    return text.lower().translate(CHAR_MAP)


def brand_analysis(hostname):
    labels = host_parts(hostname)
    best_brand = None
    best_score = 0.0
    best_label = None

    for label in labels:
        if len(label) < 3:
            continue

        normalized = normalized_token(label)

        for brand in KNOWN_BRANDS:
            score = SequenceMatcher(
                None, normalized, brand
            ).ratio()

            if normalized == brand and label != brand:
                score = 1.0

            if normalized.startswith(brand) and label != brand:
                score = max(score, 0.90)

            if score > best_score:
                best_score = score
                best_brand = brand
                best_label = label

    impersonation = (
        best_brand is not None
        and best_label != best_brand
        and best_score >= 0.75
    )

    reasons = []
    if impersonation:
        reasons.append(
            f"Domain label '{best_label}' resembles "
            f"'{best_brand}' ({round(best_score * 100)}% similarity)."
        )

    return (
        impersonation,
        best_brand,
        round(best_score * 100),
        reasons
    )


def expected_domain_analysis(hostname, expected):
    """
    Optional comparison used when an examiner gives a known
    organization/domain such as hitech9zero.examly.io.
    """
    if not expected.strip():
        return False, 0, []

    expected_value = expected.strip().lower()

    if "://" in expected_value:
        try:
            expected_value = (
                urlparse(expected_value).hostname
                or expected_value
            )
        except Exception:
            pass

    expected_value = expected_value.rstrip(".")
    actual = hostname.lower().rstrip(".")

    if (
        actual == expected_value
        or actual.endswith("." + expected_value)
    ):
        return False, 100, [
            f"Host matches the supplied expected domain "
            f"'{expected_value}'."
        ]

    actual_base = get_base_domain(actual)
    expected_base = get_base_domain(expected_value)

    full_score = round(
        SequenceMatcher(
            None, actual, expected_value
        ).ratio() * 100
    )

    base_score = round(
        SequenceMatcher(
            None, actual_base, expected_base
        ).ratio() * 100
    )

    score = max(full_score, base_score)
    suspicious = score >= 75

    reasons = []
    if suspicious:
        reasons.append(
            f"Host is similar to the supplied expected domain "
            f"('{expected_value}') but is not an exact match."
        )

    return suspicious, score, reasons


def model_prediction(features):
    if model is None:
        return None, None

    row = pd.DataFrame([{
        name: features[name]
        for name in MODEL_FEATURES
    }])

    try:
        prediction = int(model.predict(row)[0])

        probability = None
        if hasattr(model, "predict_proba"):
            probability = float(
                model.predict_proba(row)[0][1]
            )

        return prediction, probability

    except Exception:
        return None, None


def reachability_check(parsed):
    """
    Checks public DNS and website reachability.
    This does NOT decide whether a website is safe.
    Private/reserved hosts are not contacted.
    """
    host = parsed.hostname

    if not host:
        return {
            "status": "Not checked",
            "http_status": None,
            "final_url": None,
            "message": "No hostname."
        }

    try:
        addresses = socket.getaddrinfo(
            host,
            parsed.port or (
                443 if parsed.scheme == "https"
                else 80
            ),
            type=socket.SOCK_STREAM
        )

        unique_ips = sorted({
            item[4][0]
            for item in addresses
        })

        public_ips = []

        for ip_text in unique_ips:
            try:
                ip_obj = ipaddress.ip_address(ip_text)

                if not (
                    ip_obj.is_private
                    or ip_obj.is_loopback
                    or ip_obj.is_reserved
                    or ip_obj.is_link_local
                    or ip_obj.is_multicast
                ):
                    public_ips.append(ip_text)

            except ValueError:
                pass

        if not public_ips:
            return {
                "status": "Not contacted",
                "http_status": None,
                "final_url": None,
                "message": (
                    "Host resolved only to private/reserved addresses."
                )
            }

        import urllib.request
        import urllib.error

        request = urllib.request.Request(
            parsed.geturl(),
            headers={
                "User-Agent": "PhishGuard-Demo/1.0"
            },
            method="GET"
        )

        try:
            with urllib.request.urlopen(
                request, timeout=8
            ) as response:

                final_url = response.geturl()
                status = getattr(
                    response, "status", None
                )

                # Read only a small prefix.
                response.read(4096)

                return {
                    "status": "Reachable",
                    "http_status": status,
                    "final_url": final_url,
                    "message": (
                        f"Server responded with HTTP {status}."
                    )
                }

        except urllib.error.HTTPError as exc:
            return {
                "status": "Reachable",
                "http_status": exc.code,
                "final_url": parsed.geturl(),
                "message": (
                    f"Server responded with HTTP {exc.code}."
                )
            }

        except urllib.error.URLError as exc:
            return {
                "status": "Unreachable",
                "http_status": None,
                "final_url": None,
                "message": str(exc.reason)
            }

        except (TimeoutError, socket.timeout):
            return {
                "status": "Timeout",
                "http_status": None,
                "final_url": None,
                "message": "Connection timed out."
            }

        except ssl.SSLError:
            return {
                "status": "TLS/SSL error",
                "http_status": None,
                "final_url": None,
                "message": (
                    "HTTPS certificate/TLS verification failed."
                )
            }

    except socket.gaierror:
        return {
            "status": "DNS failed",
            "http_status": None,
            "final_url": None,
            "message": (
                "Domain name could not be resolved."
            )
        }

    except Exception as exc:
        return {
            "status": "Not checked",
            "http_status": None,
            "final_url": None,
            "message": type(exc).__name__
        }


def build_assessment(
    features,
    ml_prediction,
    brand_impersonation,
    expected_impersonation,
    reachability
):
    points = 0
    reasons = []

    # Structural evidence
    if features["has_at_symbol"]:
        points += 18
        reasons.append(
            "The URL contains '@', which can hide the real host."
        )

    if features["has_ip_host"]:
        points += 12
        reasons.append(
            "The host is an IP address instead of a domain name."
        )

    if features["has_punycode"]:
        points += 15
        reasons.append(
            "The domain contains punycode/IDN encoding."
        )

    if features["suspicious_tld"]:
        points += 8
        reasons.append(
            "The top-level domain is in the project's watchlist."
        )

    if features["has_suspicious_keyword"]:
        points += min(
            15,
            5 * len(features["found_keywords"])
        )
        reasons.append(
            "Suspicious URL terms detected: "
            + ", ".join(features["found_keywords"])
        )

    if features["subdomain_count"] >= 3:
        points += 10
        reasons.append(
            "The domain contains multiple subdomain levels."
        )

    if features["digit_ratio"] >= 0.30:
        points += 8
        reasons.append(
            "The hostname contains a high digit ratio."
        )

    if features["hyphen_count"] >= 2:
        points += 6
        reasons.append(
            "The hostname contains multiple hyphens."
        )

    if features["hostname_entropy"] >= 4.0:
        points += 6
        reasons.append(
            "The hostname has relatively high character entropy."
        )

    # Identity evidence
    if brand_impersonation:
        points += 30
        reasons.append(
            "Possible known-brand impersonation was detected."
        )

    if expected_impersonation:
        points += 30
        reasons.append(
            "The supplied expected domain does not match the host."
        )

    # ML evidence
    if ml_prediction == 1:
        points += 20
        reasons.append(
            "Random Forest classified the URL as phishing-like."
        )
    elif ml_prediction == 0:
        reasons.append(
            "Random Forest classified the URL as legitimate-like."
        )

    # Reachability is deliberately NOT treated as legitimacy.
    if reachability["status"] == "DNS failed":
        reasons.append(
            "The domain could not be resolved by DNS."
        )
    elif reachability["status"] == "Reachable":
        reasons.append(
            "The website responded to a connectivity check."
        )

    score = max(0, min(100, points))

    if score >= 60:
        label = "🚨 Suspicious / Likely Phishing"
    elif score >= 30:
        label = "🟡 Suspicious / Needs Verification"
    else:
        label = "🟢 No Strong Phishing Indicators"

    return score, label, reasons


# =========================================================
# STREAMLIT UI
# =========================================================

st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="wide"
)

create_database()

st.title("🛡️ PhishGuard")
st.subheader(
    "AI-Based Intelligent Phishing Domain Detection "
    "& Risk Assessment"
)

st.write(
    "PhishGuard validates a URL, checks whether the public "
    "website is reachable, extracts domain/URL evidence, "
    "uses Random Forest when available, and explains the result."
)

with st.expander("⚙️ Demo settings", expanded=True):
    expected_domain = st.text_input(
        "Optional: expected legitimate domain",
        placeholder=(
            "Example: examly.io or "
            "hitech9zero.examly.io"
        ),
        help=(
            "Use this when the examiner gives a known "
            "organization/domain to verify."
        )
    )

url_input = st.text_input(
    "🔗 Enter a website URL or domain",
    placeholder=(
        "https://example.com  or  "
        "hitech9zero.examly.io"
    )
)

analyze = st.button(
    "🔎 Analyze URL",
    width="stretch"
)

if analyze:

    normalized_url, parsed, errors = normalize_url(
        url_input
    )

    if errors:
        st.error("❌ Invalid URL")
        for error in errors:
            st.write("• " + error)

        st.info(
            "Valid examples: "
            "https://example.com  or  "
            "hitech9zero.examly.io"
        )

        st.stop()

    host = parsed.hostname.lower().rstrip(".")

    # 1. Extract URL/domain features
    features = extract_features(
        normalized_url,
        parsed
    )

    # 2. Machine-learning evidence
    ml_prediction, ml_probability = model_prediction(
        features
    )

    # 3. Known-brand impersonation evidence
    (
        brand_impersonation,
        matched_brand,
        brand_similarity,
        brand_reasons
    ) = brand_analysis(host)

    # 4. Optional examiner-provided expected-domain comparison
    (
        expected_impersonation,
        expected_similarity,
        expected_reasons
    ) = expected_domain_analysis(
        host,
        expected_domain
    )

    # 5. Actual DNS/website reachability
    reachability = reachability_check(parsed)

    # 6. Evidence fusion
    risk_score, result_label, reasons = build_assessment(
        features,
        ml_prediction,
        brand_impersonation,
        expected_impersonation,
        reachability
    )

    reasons = (
        brand_reasons
        + expected_reasons
        + reasons
    )

    reasons = list(dict.fromkeys(reasons))

    if not reasons:
        reasons = [
            "No strong suspicious indicators were detected "
            "by the current analysis rules."
        ]

    # Save scan
    if brand_impersonation:
        impersonation_text = (
            f"Possible {matched_brand} impersonation"
        )
    elif expected_impersonation:
        impersonation_text = (
            "Possible expected-domain mismatch"
        )
    else:
        impersonation_text = "None detected"

    similarity_to_save = max(
        brand_similarity,
        expected_similarity
    )

    save_scan(
        normalized_url,
        host,
        risk_score,
        result_label,
        impersonation_text,
        similarity_to_save
    )

    # =====================================================
    # RESULT
    # =====================================================

    st.divider()
    st.header("📊 Analysis Result")

    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "Risk Score",
        f"{risk_score}/100"
    )

    c2.metric(
        "Domain",
        host
    )

    c3.metric(
        "Website Status",
        reachability["status"]
    )

    c4.metric(
        "HTTPS",
        "Yes" if features["has_https"]
        else "No"
    )

    if risk_score >= 60:
        st.error(result_label)
    elif risk_score >= 30:
        st.warning(result_label)
    else:
        st.success(result_label)

    # =====================================================
    # EXPLANATION
    # =====================================================

    st.subheader(
        "🧠 Why did PhishGuard give this result?"
    )

    for reason in reasons:
        st.write("• " + reason)

    # =====================================================
    # WEBSITE STATUS
    # =====================================================

    st.subheader("🌐 URL / Website Status")

    st.write(
        f"**Normalized URL:** `{normalized_url}`"
    )

    st.write(
        f"**Domain:** `{host}`"
    )

    st.write(
        f"**DNS / HTTP status:** "
        f"**{reachability['status']}**"
    )

    if reachability["http_status"] is not None:
        st.write(
            f"**HTTP status code:** "
            f"`{reachability['http_status']}`"
        )

    if reachability["final_url"]:
        st.write(
            f"**Final URL:** "
            f"`{reachability['final_url']}`"
        )

    st.caption(
        "Important: a reachable website is not automatically "
        "legitimate, and an unreachable website is not "
        "automatically phishing."
    )

    # =====================================================
    # DOMAIN IDENTITY
    # =====================================================

    st.subheader(
        "🎭 Domain Identity / Impersonation"
    )

    if brand_impersonation:
        st.error(
            f"Possible {matched_brand} impersonation — "
            f"{brand_similarity}% similarity"
        )

    elif matched_brand:
        st.write(
            f"Closest known brand: **{matched_brand}** "
            f"({brand_similarity}% similarity). "
            "The configured impersonation threshold "
            "was not reached."
        )

    else:
        st.write(
            "No close match was found in the project's "
            "known-brand list."
        )

    if expected_domain.strip():

        if expected_impersonation:
            st.warning(
                f"Expected-domain comparison: possible "
                f"mismatch ({expected_similarity}% similarity)."
            )

        else:
            st.success(
                "Expected-domain comparison: host matches "
                "or does not strongly resemble a different domain."
            )

    # =====================================================
    # FEATURES
    # =====================================================

    st.subheader("🔬 Extracted Features")

    feature_display = {
        "URL Length": features["url_length"],
        "HTTPS": (
            "Yes" if features["has_https"]
            else "No"
        ),
        "Number of Dots": features["num_dots"],
        "Special Characters (@ - _)":
            features["num_special_chars"],
        "Suspicious Keywords":
            (
                ", ".join(features["found_keywords"])
                if features["found_keywords"]
                else "None"
            ),
        "Hostname Length":
            features["hostname_length"],
        "Subdomain Count":
            features["subdomain_count"],
        "Digit Ratio":
            features["digit_ratio"],
        "IP Host":
            (
                "Yes" if features["has_ip_host"]
                else "No"
            ),
        "@ Symbol":
            (
                "Yes" if features["has_at_symbol"]
                else "No"
            ),
        "Punycode":
            (
                "Yes" if features["has_punycode"]
                else "No"
            ),
        "Suspicious TLD":
            (
                "Yes" if features["suspicious_tld"]
                else "No"
            ),
        "Path Length":
            features["path_length"],
        "Query Length":
            features["query_length"],
        "Hostname Entropy":
            features["hostname_entropy"],
    }

    st.dataframe(
        pd.DataFrame(
            feature_display.items(),
            columns=["Feature", "Value"]
        ),
        width="stretch",
        hide_index=True
    )

    # =====================================================
    # RANDOM FOREST
    # =====================================================

    st.subheader("🤖 Random Forest")

    if ml_prediction is None:

        st.warning(
            "Random Forest model was not available for "
            "this scan. The URL/domain evidence engine "
            "still performed the analysis."
        )

    else:

        st.write(
            "**Model prediction:** "
            + (
                "Phishing-like"
                if ml_prediction == 1
                else "Legitimate-like"
            )
        )

        if ml_probability is not None:
            st.write(
                "**Model phishing probability:** "
                f"{ml_probability:.2%}"
            )

        st.caption(
            "Random Forest is treated as one evidence "
            "source, not the sole decision-maker."
        )


# =========================================================
# SCAN HISTORY
# =========================================================

st.divider()
st.header("📜 Scan History")

try:

    conn = sqlite3.connect(DB_FILE)

    history = pd.read_sql_query(
        """
        SELECT
            url AS URL,
            domain AS Domain,
            risk_score AS "Risk Score",
            result AS Result,
            impersonation AS Impersonation,
            similarity AS "Similarity %",
            scan_time AS "Scan Time"
        FROM scan_history
        ORDER BY id DESC
        LIMIT 50
        """,
        conn
    )

    conn.close()

    if history.empty:
        st.info("No scan history yet.")

    else:
        st.dataframe(
            history,
            width="stretch",
            hide_index=True
        )

except Exception as exc:

    st.warning(
        f"Could not load scan history: "
        f"{type(exc).__name__}"
    )


st.divider()

st.caption(
    "PhishGuard is a student prototype. "
    "Its result is an assessment, not proof that "
    "a website is safe or malicious."
)
