import streamlit as st
from urllib.parse import urlparse
from difflib import SequenceMatcher
import pandas as pd
import joblib
import sqlite3
from datetime import datetime


# =========================================================
# LOAD RANDOM FOREST MODEL
# =========================================================

model = joblib.load("phishguard_model.pkl")


# =========================================================
# DATABASE SETUP
# =========================================================

def create_database():

    connection = sqlite3.connect("phishguard.db")

    cursor = connection.cursor()

    cursor.execute("""
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

    connection.commit()
    connection.close()


create_database()


# =========================================================
# SAVE SCAN HISTORY
# =========================================================

def save_scan(
    url,
    domain,
    risk_score,
    result,
    impersonation,
    similarity
):

    connection = sqlite3.connect("phishguard.db")

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO scan_history
        (url, domain, risk_score, result,
         impersonation, similarity, scan_time)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        url,
        domain,
        risk_score,
        result,
        impersonation,
        similarity,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    connection.commit()
    connection.close()


# =========================================================
# DOMAIN IMPERSONATION FUNCTION
# =========================================================

def check_impersonation(domain):

    known_brands = [
        "google",
        "paypal",
        "amazon",
        "microsoft",
        "apple",
        "facebook",
        "instagram"
    ]

    # Remove port number and convert to lowercase
    host = domain.lower().split(":")[0]

    # Split domain into labels and ignore www
    labels = [
        part for part in host.split(".")
        if part and part != "www"
    ]

    best_match = None
    best_similarity = 0
    impersonation_detected = False

    for label in labels:

        # Normalize common character substitutions
        normalized_label = label.replace("1", "l")
        normalized_label = normalized_label.replace("0", "o")
        normalized_label = normalized_label.replace("3", "e")
        normalized_label = normalized_label.replace("5", "s")

        for brand in known_brands:

            similarity = SequenceMatcher(
                None,
                normalized_label,
                brand
            ).ratio()

            # Strong indicator: normalized label matches the brand,
            # but the original label is different.
            if normalized_label == brand and label != brand:
                similarity = 1.0

            # Brand written as a prefix
            if normalized_label.startswith(brand) and label != brand:
                similarity = max(similarity, 0.90)

            if similarity > best_similarity:
                best_similarity = similarity
                best_match = brand

                # Do not flag the genuine brand domain
                if label != brand and similarity >= 0.75:
                    impersonation_detected = True

    return (
        impersonation_detected,
        best_match,
        round(best_similarity * 100)
    )


# =========================================================
# PAGE CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="wide"
)


# =========================================================
# HEADER
# =========================================================

st.title("🛡️ PhishGuard")

st.subheader(
    "AI-Based Intelligent Phishing Domain Detection System"
)

st.write(
    "Analyze a URL using Random Forest machine learning, "
    "domain impersonation analysis, and explainable risk assessment."
)

st.divider()


# =========================================================
# URL INPUT
# =========================================================

st.header("🔍 Analyze a URL")

url = st.text_input(
    "Enter a website URL",
    placeholder="Example: https://example.com"
)

verification_limited = st.checkbox(
    "🔐 This URL requires login or restricted access"
)


# =========================================================
# ANALYZE BUTTON
# =========================================================

if st.button(
    "🔎 Analyze URL",
    use_container_width=True
):

    if not url:

        st.warning("⚠️ Please enter a URL.")

    else:

        # Add HTTPS if protocol is missing
        if not url.startswith(
            ("http://", "https://")
        ):

            url = "https://" + url


        # =================================================
        # PARSE URL
        # =================================================

        parsed = urlparse(url)

        domain = parsed.netloc


        # =================================================
        # FEATURE EXTRACTION
        # =================================================

        url_length = len(url)

        has_https = int(
            url.startswith("https://")
        )

        num_dots = url.count(".")

        num_special_chars = sum(
            url.count(char)
            for char in ["@", "-", "_"]
        )

        suspicious_keywords = [
            "login",
            "verify",
            "update",
            "secure",
            "account",
            "bank",
            "confirm",
            "password"
        ]

        has_suspicious_keyword = int(
            any(
                word in url.lower()
                for word in suspicious_keywords
            )
        )

        found_keywords = [
            word
            for word in suspicious_keywords
            if word in url.lower()
        ]


        # =================================================
        # RANDOM FOREST PREDICTION
        # =================================================

        features = pd.DataFrame(
            [[
                url_length,
                has_https,
                num_dots,
                num_special_chars,
                has_suspicious_keyword
            ]],
            columns=[
                "url_length",
                "has_https",
                "num_dots",
                "num_special_chars",
                "has_suspicious_keyword"
            ]
        )

        prediction = model.predict(features)[0]


        # =================================================
        # DOMAIN IMPERSONATION
        # =================================================

        (
            is_impersonation,
            matched_brand,
            similarity
        ) = check_impersonation(domain)


        # =================================================
        # FINAL RESULT
        # =================================================

        if verification_limited:

    result = "🟡 Unverified"

elif prediction == 1 or is_impersonation:

    result = "🚨 Likely Phishing"

else:

    result = "✅ Likely Legitimate"

        # =================================================
        # RISK SCORE
        # =================================================

        if verification_limited:

            risk_score = 50

        else:

            if prediction == 1:

                risk_score = 75

            else:

                risk_score = 20

            if is_impersonation:

                risk_score += 20

            risk_score = min(
                risk_score,
                100
            )


        # =================================================
        # SAVE SCAN TO DATABASE
        # =================================================

        if is_impersonation:

            impersonation_text = (
                f"Possible {matched_brand} impersonation"
            )

        else:

            impersonation_text = "None detected"


        save_scan(
            url,
            domain,
            risk_score,
            result,
            impersonation_text,
            similarity
        )


        # =================================================
        # ANALYSIS RESULT
        # =================================================

        st.divider()

        st.header("📊 Analysis Result")

        col1, col2 = st.columns(2)

        with col1:

            st.metric(
                "Risk Score",
                f"{risk_score}/100"
            )

        with col2:

            st.write("### Result")

            if verification_limited:

                st.warning(result)

            elif prediction == 1:

                st.error(result)

            else:

                st.success(result)


        # =================================================
        # DOMAIN
        # =================================================

        st.write("### 🌐 Domain")

        st.code(domain)


        # =================================================
        # DOMAIN IMPERSONATION
        # =================================================

        st.write("### 🎭 Domain Impersonation")

        if is_impersonation:

            st.warning(
                f"Possible impersonation of "
                f"**{matched_brand}**"
            )

            st.write(
                f"Similarity: **{similarity}%**"
            )

        else:

            st.success(
                "No obvious brand impersonation detected."
            )


        # =================================================
        # VERIFICATION STATUS
        # =================================================

        st.write("### 🔐 Verification Status")

        if verification_limited:

            st.warning(
                "Verification is limited because the URL "
                "requires login or restricted access."
            )

            st.info(
                "The system does not automatically classify "
                "an inaccessible or authentication-protected "
                "URL as phishing."
            )

        else:

            st.success(
                "Normal verification mode."
            )


        # =================================================
        # EXTRACTED FEATURES
        # =================================================

        st.write("### 🔎 Extracted Features")

        col1, col2 = st.columns(2)

        with col1:

            st.write(
                f"**URL Length:** {url_length}"
            )

            st.write(
                f"**HTTPS:** "
                f"{'Yes' if has_https else 'No'}"
            )

            st.write(
                f"**Number of Dots:** {num_dots}"
            )

        with col2:

            st.write(
                f"**Special Characters:** "
                f"{num_special_chars}"
            )

            st.write(
                f"**Suspicious Keyword:** "
                f"{'Yes' if has_suspicious_keyword else 'No'}"
            )

            if found_keywords:

                st.write(
                    "**Detected Keywords:** "
                    + ", ".join(found_keywords)
                )


        # =================================================
        # MACHINE LEARNING MODEL
        # =================================================

        st.write("### 🤖 Machine Learning Model")

        st.info(
            "Random Forest classifier trained on "
            "URL-based features."
        )


# =========================================================
# SCAN HISTORY
# =========================================================

st.divider()

st.header("📜 Scan History")

connection = sqlite3.connect("phishguard.db")

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
    """,
    connection
)

connection.close()


if not history.empty:

    st.dataframe(
        history,
        use_container_width=True,
        hide_index=True
    )

else:

    st.info(
        "No scan history available yet."
    )


# =========================================================
# FEATURES SECTION
# =========================================================

st.divider()

st.header("🛡️ What PhishGuard Analyzes")

col1, col2, col3 = st.columns(3)

with col1:

    st.subheader("🤖 Random Forest")

    st.write(
        "Analyzes URL and domain features using "
        "a machine-learning classifier."
    )

with col2:

    st.subheader("🎭 Impersonation Detection")

    st.write(
        "Identifies possible brand impersonation "
        "and typosquatting."
    )

with col3:

    st.subheader("📊 Risk Assessment")

    st.write(
        "Provides a project-defined 0–100 risk score "
        "with supporting evidence."
    )


# =========================================================
# FOOTER
# =========================================================

st.divider()

st.caption(
    "PhishGuard | AI-Based Intelligent Phishing "
    "Domain Detection System"
)
