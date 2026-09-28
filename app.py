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
# DOMAIN IMPERSONATION DETECTION
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

    # Split domain labels and ignore www
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

            # Strong indicator:
            # paypa1 -> paypal
            if normalized_label == brand and label != brand:
                similarity = 1.0

            # Brand written as a prefix
            if normalized_label.startswith(brand) and label != brand:
                similarity = max(similarity, 0.90)

            if similarity > best_similarity:

                best_similarity = similarity
                best_match = brand

                # Do not flag genuine brand domains
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
    layout="wide",
    initial_sidebar_state="collapsed"
)


# =========================================================
# ATTRACTIVE CYBERSECURITY UI
# =========================================================

st.markdown("""
<style>

    /* =========================================
       MAIN BACKGROUND
       ========================================= */

    .stApp {
        background:
            radial-gradient(
                circle at 10% 10%,
                rgba(99,102,241,0.18),
                transparent 28%
            ),
            radial-gradient(
                circle at 90% 20%,
                rgba(168,85,247,0.16),
                transparent 30%
            ),
            radial-gradient(
                circle at 50% 100%,
                rgba(14,165,233,0.12),
                transparent 30%
            ),
            linear-gradient(
                135deg,
                #f8faff 0%,
                #eef2ff 50%,
                #f0f9ff 100%
            );
    }


    /* =========================================
       REMOVE EXTRA TOP SPACE
       ========================================= */

    .block-container {
        padding-top: 2rem;
        padding-bottom: 3rem;
    }


    /* =========================================
       HEADINGS
       ========================================= */

    h1 {
        text-align: center !important;
        font-size: 3.2rem !important;
        font-weight: 900 !important;
        color: #312e81 !important;
        letter-spacing: -1px;
    }

    h2 {
        color: #3730a3 !important;
        font-weight: 800 !important;
    }

    h3 {
        color: #4338ca !important;
        font-weight: 750 !important;
    }


    /* =========================================
       SUBTITLE
       ========================================= */

    .subtitle {
        text-align: center;
        font-size: 1.15rem;
        color: #475569;
        margin-top: -15px;
        margin-bottom: 10px;
    }


    /* =========================================
       HERO CARD
       ========================================= */

    .hero-card {
        background:
            linear-gradient(
                135deg,
                rgba(79,70,229,0.96),
                rgba(124,58,237,0.96)
            );

        padding: 28px;
        border-radius: 22px;
        color: white;
        margin: 20px 0 25px 0;

        box-shadow:
            0 15px 35px rgba(79,70,229,0.25);

        border: 1px solid rgba(255,255,255,0.25);
    }

    .hero-card h2 {
        color: white !important;
        margin-bottom: 8px;
    }

    .hero-card p {
        color: #eef2ff;
        font-size: 1rem;
    }


    /* =========================================
       SCANNER CARD
       ========================================= */

    .scanner-card {
        background: rgba(255,255,255,0.90);
        border: 1px solid #c7d2fe;
        border-radius: 20px;
        padding: 24px;

        box-shadow:
            0 10px 30px rgba(30,41,59,0.08);

        margin-bottom: 20px;
    }


    /* =========================================
       RESULT CARDS
       ========================================= */

    .result-danger {
        background: linear-gradient(
            135deg,
            #fff1f2,
            #ffe4e6
        );

        border-left: 7px solid #ef4444;
        border-radius: 16px;
        padding: 20px;
        margin: 10px 0;

        box-shadow:
            0 8px 20px rgba(239,68,68,0.12);
    }

    .result-safe {
        background: linear-gradient(
            135deg,
            #f0fdf4,
            #dcfce7
        );

        border-left: 7px solid #22c55e;
        border-radius: 16px;
        padding: 20px;
        margin: 10px 0;

        box-shadow:
            0 8px 20px rgba(34,197,94,0.12);
    }

    .result-warning {
        background: linear-gradient(
            135deg,
            #fffbeb,
            #fef3c7
        );

        border-left: 7px solid #f59e0b;
        border-radius: 16px;
        padding: 20px;
        margin: 10px 0;

        box-shadow:
            0 8px 20px rgba(245,158,11,0.12);
    }


    .result-title {
        font-size: 1.45rem;
        font-weight: 850;
        margin-bottom: 5px;
    }

    .result-text {
        color: #475569;
        font-size: 0.95rem;
    }


    /* =========================================
       EVIDENCE CARDS
       ========================================= */

    .info-card {
        background: rgba(255,255,255,0.92);
        border-radius: 18px;
        padding: 20px;

        border: 1px solid #dbeafe;

        box-shadow:
            0 8px 22px rgba(15,23,42,0.07);

        min-height: 145px;
        margin-bottom: 15px;
    }

    .info-card-purple {
        border-top: 5px solid #8b5cf6;
    }

    .info-card-orange {
        border-top: 5px solid #f97316;
    }

    .info-card-green {
        border-top: 5px solid #22c55e;
    }

    .info-card-blue {
        border-top: 5px solid #3b82f6;
    }

    .card-title {
        font-size: 1.1rem;
        font-weight: 800;
        color: #312e81;
        margin-bottom: 8px;
    }

    .card-text {
        color: #64748b;
        line-height: 1.5;
    }


    /* =========================================
       URL INPUT
       ========================================= */

    .stTextInput input {
        border: 2px solid #818cf8 !important;
        border-radius: 13px !important;
        background: white !important;
        padding: 13px !important;
        font-size: 1rem !important;

        box-shadow:
            0 4px 12px rgba(79,70,229,0.08);
    }

    .stTextInput input:focus {
        border-color: #4f46e5 !important;

        box-shadow:
            0 0 0 3px rgba(99,102,241,0.15) !important;
    }


    /* =========================================
       BUTTON
       ========================================= */

    .stButton > button {

        background:
            linear-gradient(
                90deg,
                #4f46e5,
                #7c3aed
            ) !important;

        color: white !important;

        border: none !important;
        border-radius: 13px !important;

        padding: 0.75rem 1rem !important;

        font-size: 1.05rem !important;
        font-weight: 800 !important;

        box-shadow:
            0 8px 18px rgba(79,70,229,0.28);

        transition: all 0.2s ease;
    }

    .stButton > button:hover {

        transform: translateY(-2px);

        box-shadow:
            0 12px 25px rgba(79,70,229,0.35);
    }


    /* =========================================
       METRIC CARDS
       ========================================= */

    [data-testid="stMetric"] {

        background: rgba(255,255,255,0.95);

        padding: 20px;

        border-radius: 18px;

        border: 1px solid #c7d2fe;

        box-shadow:
            0 8px 20px rgba(15,23,42,0.08);
    }

    [data-testid="stMetricLabel"] {
        color: #6366f1 !important;
        font-weight: 700 !important;
    }

    [data-testid="stMetricValue"] {
        color: #312e81 !important;
        font-weight: 900 !important;
    }


    /* =========================================
       CHECKBOX
       ========================================= */

    [data-testid="stCheckbox"] {
        background: rgba(255,255,255,0.75);
        padding: 8px 14px;
        border-radius: 12px;
        border: 1px solid #c7d2fe;
    }


    /* =========================================
       ALERTS
       ========================================= */

    [data-testid="stAlert"] {
        border-radius: 14px !important;
    }


    /* =========================================
       CODE BOX
       ========================================= */

    code {
        border-radius: 10px !important;
    }


    /* =========================================
       DATAFRAME
       ========================================= */

    [data-testid="stDataFrame"] {
        border-radius: 16px;
        overflow: hidden;

        box-shadow:
            0 8px 20px rgba(15,23,42,0.08);
    }


    /* =========================================
       FEATURE CARDS
       ========================================= */

    .feature-card {
        background: rgba(255,255,255,0.92);

        border-radius: 18px;

        padding: 22px;

        min-height: 180px;

        border: 1px solid #e0e7ff;

        box-shadow:
            0 8px 22px rgba(15,23,42,0.07);

        transition: transform 0.2s ease;
    }

    .feature-card:hover {
        transform: translateY(-4px);
    }

    .feature-icon {
        font-size: 2.2rem;
        margin-bottom: 8px;
    }

    .feature-title {
        font-size: 1.15rem;
        font-weight: 850;
        color: #3730a3;
        margin-bottom: 8px;
    }

    .feature-text {
        color: #64748b;
        line-height: 1.5;
    }


    /* =========================================
       FOOTER
       ========================================= */

    .footer {
        text-align: center;
        color: #64748b;
        padding: 20px;
        font-size: 0.9rem;
    }


</style>
""", unsafe_allow_html=True)


# =========================================================
# HEADER
# =========================================================

st.markdown("""
<div class="hero-card">

    <h2>🛡️ PhishGuard</h2>

    <p>
        AI-powered phishing domain detection,
        domain impersonation analysis and
        risk assessment.
    </p>

</div>
""", unsafe_allow_html=True)

st.markdown(
    '<div class="subtitle">'
    '🔐 Intelligent URL Security Analysis using Random Forest'
    '</div>',
    unsafe_allow_html=True
)


# =========================================================
# URL SCANNER
# =========================================================

st.markdown("""
<div class="scanner-card">

    <h3>🔍 Scan a Website</h3>

    <p style="color:#64748b;">
        Enter a website URL below to analyze its
        security characteristics.
    </p>

</div>
""", unsafe_allow_html=True)


url = st.text_input(
    "Website URL",
    placeholder="Example: https://example.com",
    label_visibility="collapsed"
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

        # =================================================
        # ADD HTTPS IF PROTOCOL IS MISSING
        # =================================================

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
        # SAVE SCAN
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


        # Risk score + domain
        col1, col2 = st.columns(2)


        with col1:

            st.metric(
                "🛡️ Risk Score",
                f"{risk_score}/100"
            )


        with col2:

            st.metric(
                "🎯 Similarity",
                f"{similarity}%"
            )


        # =================================================
        # RESULT CARD
        # =================================================

        if verification_limited:

            st.markdown("""
            <div class="result-warning">

                <div class="result-title">
                    🟡 Unverified
                </div>

                <div class="result-text">
                    Verification is limited because this
                    URL requires login or restricted access.
                </div>

            </div>
            """, unsafe_allow_html=True)


        elif prediction == 1 or is_impersonation:

            st.markdown("""
            <div class="result-danger">

                <div class="result-title">
                    🚨 Likely Phishing
                </div>

                <div class="result-text">
                    The system detected one or more
                    suspicious indicators.
                </div>

            </div>
            """, unsafe_allow_html=True)


        else:

            st.markdown("""
            <div class="result-safe">

                <div class="result-title">
                    ✅ Likely Legitimate
                </div>

                <div class="result-text">
                    No major phishing indicators were
                    detected by the current analysis.
                </div>

            </div>
            """, unsafe_allow_html=True)


        # =================================================
        # DOMAIN + ML EVIDENCE
        # =================================================

        st.subheader("🔎 Detection Evidence")


        evidence1, evidence2 = st.columns(2)


        with evidence1:

            if is_impersonation:

                st.markdown(f"""
                <div class="info-card info-card-orange">

                    <div class="card-title">
                        🎭 Brand Impersonation
                    </div>

                    <div class="card-text">
                        Possible impersonation of
                        <b>{matched_brand}</b>.<br><br>

                        Similarity:
                        <b>{similarity}%</b>
                    </div>

                </div>
                """, unsafe_allow_html=True)

            else:

                st.markdown("""
                <div class="info-card info-card-green">

                    <div class="card-title">
                        🎭 Brand Impersonation
                    </div>

                    <div class="card-text">
                        No obvious known-brand
                        impersonation detected.
                    </div>

                </div>
                """, unsafe_allow_html=True)


        with evidence2:

            ml_result = (
                "Phishing"
                if prediction == 1
                else "Likely Legitimate"
            )

            st.markdown(f"""
            <div class="info-card info-card-purple">

                <div class="card-title">
                    🤖 Random Forest
                </div>

                <div class="card-text">
                    Model prediction:
                    <b>{ml_result}</b><br><br>

                    Five URL-based features were
                    analyzed by the classifier.
                </div>

            </div>
            """, unsafe_allow_html=True)


        # =================================================
        # DOMAIN
        # =================================================

        st.subheader("🌐 Domain")

        st.code(domain)


        # =================================================
        # VERIFICATION STATUS
        # =================================================

        st.subheader("🔐 Verification Status")


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

        st.subheader("🧩 Extracted URL Features")


        f1, f2, f3, f4, f5 = st.columns(5)


        with f1:

            st.metric(
                "URL Length",
                url_length
            )


        with f2:

            st.metric(
                "HTTPS",
                "Yes" if has_https else "No"
            )


        with f3:

            st.metric(
                "Dots",
                num_dots
            )


        with f4:

            st.metric(
                "Special Chars",
                num_special_chars
            )


        with f5:

            st.metric(
                "Suspicious",
                "Yes" if has_suspicious_keyword else "No"
            )


        if found_keywords:

            st.info(
                "🔎 Detected keywords: "
                + ", ".join(found_keywords)
            )


        # =================================================
        # MACHINE LEARNING MODEL
        # =================================================

        st.subheader("🤖 Machine Learning Model")

        st.markdown("""
        <div class="info-card info-card-blue">

            <div class="card-title">
                🌲 Random Forest Classifier
            </div>

            <div class="card-text">
                PhishGuard uses a Random Forest classifier
                trained using URL-based features such as
                URL length, HTTPS usage, number of dots,
                special characters and suspicious keywords.
            </div>

        </div>
        """, unsafe_allow_html=True)


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
        "📭 No scan history available yet."
    )


# =========================================================
# WHAT PHISHGUARD ANALYZES
# =========================================================

st.divider()

st.header("🛡️ What PhishGuard Analyzes")


col1, col2, col3 = st.columns(3)


with col1:

    st.markdown("""
    <div class="feature-card">

        <div class="feature-icon">
            🤖
        </div>

        <div class="feature-title">
            Random Forest
        </div>

        <div class="feature-text">
            Analyzes URL-based features using
            a machine-learning classifier.
        </div>

    </div>
    """, unsafe_allow_html=True)


with col2:

    st.markdown("""
    <div class="feature-card">

        <div class="feature-icon">
            🎭
        </div>

        <div class="feature-title">
            Impersonation Detection
        </div>

        <div class="feature-text">
            Identifies possible brand impersonation,
            character substitutions and suspicious
            domain similarities.
        </div>

    </div>
    """, unsafe_allow_html=True)


with col3:

    st.markdown("""
    <div class="feature-card">

        <div class="feature-icon">
            📊
        </div>

        <div class="feature-title">
            Risk Assessment
        </div>

        <div class="feature-text">
            Provides a project-defined 0–100
            risk score with supporting evidence.
        </div>

    </div>
    """, unsafe_allow_html=True)


# =========================================================
# FOOTER
# =========================================================

st.divider()

st.markdown("""
<div class="footer">

    🛡️ <b>PhishGuard</b><br>

    AI-Based Intelligent Phishing Domain Detection System<br>

    <small>
        Random Forest • Domain Impersonation Analysis • Risk Assessment
    </small>

</div>
""", unsafe_allow_html=True)
