import json
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
import streamlit as st

st.set_page_config(page_title="ScamShield AI", page_icon="🛡️", layout="wide")

SCAM_PATTERNS = {
    "Urgent or threatening language": [
        r"\burgent\b", r"\bimmediately\b", r"\bact now\b",
        r"\baccount.{0,25}(blocked|suspended|closed)\b",
        r"\b(will be|has been) blocked\b", r"\blast warning\b",
        r"mee\s+bank\s+account\s+(?:block|blocked|avuthundi|avutundi)",
        r"account\s+(?:block|blocked)\s+avuthundi", r"ventane\s+(?:cheyyandi|cheyandi|respond)",
        r"urgent\s+ga", r"immediate\s+ga", r"leka pothe.{0,30}(?:block|suspend)",
    ],
    "Requests for sensitive information": [
        r"\botp\b", r"\bpin\b", r"\bpassword\b", r"\bverification code\b",
        r"\bbank details\b", r"\bcard details\b",
        r"\bshare.{0,20}(credentials|code|details)\b",
        r"\botp\s+(?:share|send|cheyyandi|cheyandi)",
        r"(?:otp|pin|password)\s+(?:ivvandi|pampandi|cheppandi|share\s+cheyyandi)",
        r"(?:mee|your)\s+(?:otp|pin|password)\s+(?:ivvandi|pampandi|cheppandi)",
        r"bank\s+details\s+(?:ivvandi|pampandi|share\s+cheyyandi)",
    ],
    "Money or payment requests": [
        r"\b(pay|payment|transfer|send)\b.{0,35}\b(money|fee|amount|cash|rupees|rs\.?|inr)\b",
        r"\bprocessing fee\b", r"\bpay.{0,20}(now|first|to claim|to activate)\b",
        r"\bguaranteed returns?\b", r"\bdouble your money\b",
        r"(?:fee|money|amount)\s+(?:pay|send)\s+cheyyandi",
        r"(?:dabbu|dabbulu)\s+(?:pampandi|kattandi|pay\s+cheyyandi)",
        r"processing\s+fee\s+(?:pay\s+)?cheyyandi",
    ],
    "Prize or reward claims": [
        r"\bwon\b", r"\bwinner\b", r"\bfree gift\b",
        r"\bclaim your prize\b", r"\blottery\b",
        r"(?:meeru|meeku)\s+(?:prize|gift|bahumathi)\s+(?:vachindi|geluchukunnaru|gelicharu)",
        r"(?:prize|gift|bahumathi)\s+claim\s+cheyyandi",
        r"congratulations.{0,40}(?:prize|gift|bahumathi)",
    ],
    "Suspicious job or investment offer": [
        r"\bwork from home\b", r"\bearn money fast\b",
        r"\bno experience.{0,20}(needed|required)\b",
        r"\bactivate your account\b", r"\bguaranteed profit\b",
        r"work\s+from\s+home.{0,40}(?:earn|money|income|sampadinchandi)",
        r"(?:rojuki|daily)\s+(?:easy\s+)?income", r"investment\s+cheste.{0,30}(?:profit|returns)",
    ],
}

HISTORY_FILE = Path(__file__).with_name("analysis_history.json")


def find_suspicious_urls(text):
    """Find URLs and report basic warning signs; this is not a live reputation check."""
    candidates = re.findall(r"(?i)\b(?:https?://|www\.)[^\s<>'\"]+", text)
    results = []
    for candidate in candidates:
        cleaned_url = candidate.rstrip(".,!?;:)]}")
        normalized = cleaned_url if cleaned_url.lower().startswith(("http://", "https://")) else "https://" + cleaned_url
        try:
            parsed = urlparse(normalized)
            hostname = (parsed.hostname or "").lower()
        except ValueError:
            parsed = urlparse("")
            hostname = ""

        reasons = []
        if not hostname:
            reasons.append("The link could not be parsed correctly.")
        if parsed.scheme.lower() == "http":
            reasons.append("The link uses HTTP instead of HTTPS.")
        if hostname.startswith("xn--") or ".xn--" in hostname:
            reasons.append("The domain uses punycode, which can sometimes disguise lookalike characters.")
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", hostname):
            reasons.append("The link uses an IP address instead of a normal domain name.")
        if hostname.count("-") >= 3:
            reasons.append("The domain contains several hyphens.")
        if "@" in normalized:
            reasons.append("The URL contains an @ symbol, which can make the destination confusing.")
        results.append({"url": cleaned_url, "reasons": reasons})
    return results


def inspect_url(raw_url):
    """Inspect a single URL for visible warning signs; never visits the site."""
    candidate = raw_url.strip().strip("<>").rstrip(".,!?;:)]}")
    if not candidate:
        return {"url": candidate, "valid": False, "reasons": ["Enter a URL or domain to inspect."], "score": 0}

    normalized = candidate if re.match(r"(?i)^https?://", candidate) else "https://" + candidate
    try:
        parsed = urlparse(normalized)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        # Accessing .port can raise ValueError for malformed ports.
        port = parsed.port
    except ValueError:
        return {"url": candidate, "valid": False, "reasons": ["This URL appears malformed (for example, an invalid port)."], "score": 20}

    reasons = []
    if not hostname or "." not in hostname and not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", hostname):
        reasons.append("The domain name looks incomplete or could not be parsed.")
    if parsed.scheme.lower() == "http":
        reasons.append("It uses HTTP instead of HTTPS; the connection may not be encrypted.")
    if hostname.startswith("xn--") or ".xn--" in hostname:
        reasons.append("The domain uses punycode, which can sometimes disguise lookalike characters.")
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", hostname):
        reasons.append("It uses an IP address instead of a typical domain name.")
    if hostname.count("-") >= 3:
        reasons.append("The domain contains several hyphens.")
    if "@" in normalized:
        reasons.append("The URL contains an @ symbol, which can make the destination confusing.")
    if len(hostname) > 45:
        reasons.append("The domain name is unusually long.")
    if len(hostname.split(".")) >= 5:
        reasons.append("The domain has many subdomain levels; check the actual registered domain carefully.")
    if port is not None and port not in (80, 443):
        reasons.append(f"It uses a non-standard web port ({port}).")
    suspicious_words = ("login", "verify", "secure", "account", "update", "wallet", "claim", "gift", "bonus")
    if any(word in hostname for word in suspicious_words):
        reasons.append("The domain includes words often used in imitation login or reward links; verify it independently.")

    score = min(100, len(reasons) * 15)
    return {"url": candidate, "valid": bool(hostname), "reasons": reasons, "score": score}


def analyze_message(message):
    """Return a rule-based risk estimate, matched signals, and URL warnings."""
    matches = []
    for category, patterns in SCAM_PATTERNS.items():
        if any(re.search(pattern, message, flags=re.IGNORECASE) for pattern in patterns):
            matches.append(category)

    urls = find_suspicious_urls(message)
    if urls:
        matches.append("Contains a link")

    # Demonstration score, not a calibrated probability.
    score = min(100, len(matches) * 20 + sum(len(item["reasons"]) * 10 for item in urls))
    asks_for_secret = re.search(
        r"\b(otp|one[- ]time password|pin|password|verification code)\b|(?:otp|pin|password).{0,20}(?:ivvandi|pampandi|cheppandi|share\s+cheyyandi)",
        message, re.IGNORECASE,
    )
    asks_to_share = re.search(
        r"\b(share|send|reveal|provide|tell|enter|submit)\b|(?:ivvandi|pampandi|cheppandi|share\s+cheyyandi)",
        message, re.IGNORECASE,
    )
    if asks_for_secret and asks_to_share:
        score = max(score, 75)
    if not message.strip():
        score = 0

    verdict = "High risk" if score >= 60 else "Caution" if score >= 25 else "Lower risk"
    return verdict, score, matches, urls


def load_history():
    try:
        if HISTORY_FILE.exists():
            data = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        st.warning("Saved history could not be read. A fresh history will be used.")
    return []


def save_history(history):
    HISTORY_FILE.write_text(json.dumps(history, indent=2, ensure_ascii=False), encoding="utf-8")


st.markdown("""
<style>
:root { color-scheme: dark; }
.stApp { background: linear-gradient(180deg, #08111f 0%, #0d1728 52%, #0a1422 100%); color: #eef4ff; }
[data-testid="stHeader"] { background: rgba(0, 0, 0, 0); }
.block-container { max-width: 1240px; padding-top: 1.35rem; padding-bottom: 3rem; }
[data-testid="stSidebar"] { background: #0b1525; border-right: 1px solid #1e314b; }
[data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2, [data-testid="stSidebar"] h3 { color: #e7f7ff; }
.hero { padding: 2rem 2.1rem; border: 1px solid #24546a; border-radius: 24px;
        background: radial-gradient(ellipse at 88% 12%, rgba(20,184,166,.24), transparent 35%),
                    linear-gradient(125deg, #101c31 0%, #102b3d 58%, #103b45 100%);
        margin-bottom: 1rem; box-shadow: 0 18px 48px rgba(0,0,0,.18); }
.hero h1 { font-size: clamp(2rem, 4vw, 2.8rem); line-height: 1.15; margin-bottom: .45rem; color: #f5fbff; letter-spacing: -.035em; }
.hero p { font-size: 1.02rem; color: #d6e8f5; }
.hero p strong { color: #5eead4; font-size: 1.12rem; }
.small-note { color: #a9bfd3; font-size: .88rem; }
.tip-card { padding: 1rem 1.2rem; border-radius: 16px; border: 1px solid #765b2d;
            background: linear-gradient(110deg, #292416, #201e1b); margin: .8rem 0 1.25rem; color: #ffedc2; }
.info-card { padding: 1.1rem 1.2rem; border-radius: 18px; border: 1px solid #29445d;
             background: linear-gradient(145deg, #111e31, #101a2b); height: 100%; box-shadow: 0 10px 28px rgba(0,0,0,.12); }
.info-card h3 { margin-top: 0; font-size: 1.08rem; color: #a5f3fc; }
[data-testid="stMetric"] { background: linear-gradient(145deg, #122238, #101b2d); border: 1px solid #2a4059; padding: 1rem 1.05rem; border-radius: 17px; }
[data-testid="stMetricLabel"] { color: #b9cce0; }
[data-testid="stMetricValue"] { color: #f3f8ff; }
.stButton > button, [data-testid="stDownloadButton"] button { border-radius: 12px; font-weight: 650; min-height: 2.8rem; border: 1px solid #2b7180; }
.stButton > button[kind="primary"] { background: linear-gradient(100deg, #0f9f91, #087e8b); color: white; }
.stButton > button:hover, [data-testid="stDownloadButton"] button:hover { border-color: #5eead4; color: #ffffff; }
.stTextArea textarea, .stTextInput input, [data-baseweb="select"] > div { background: #0d192a; border-color: #2b4059; border-radius: 12px; }
.stTabs [data-baseweb="tab-list"] { gap: .45rem; border-bottom: 1px solid #263b53; }
.stTabs [data-baseweb="tab"] { background: #101c2e; border: 1px solid #243850; border-radius: 12px 12px 0 0; padding: .65rem 1rem; }
.stTabs [aria-selected="true"] { background: #123345; border-color: #287e88; color: #9ff8e8; }
hr { border-color: #243850; }
@media (max-width: 700px) { .block-container { padding-left: 1rem; padding-right: 1rem; } .hero { padding: 1.35rem; border-radius: 18px; } }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="hero">
  <h1>🛡️ ScamShield AI</h1>
  <p><strong>Pause. Check. Stay safe.</strong></p>
  <p>Check suspicious messages and links before you click, pay, or share personal information.</p>
  <p class="small-note">Hackathon prototype · Transparent text-pattern analysis · Basic URL warning checks</p>
</div>
<div class="tip-card">
  <strong>⚠️ Safety tip</strong><br>
  Never share an OTP, PIN, password, or banking details with someone who contacts you unexpectedly.
</div>
""", unsafe_allow_html=True)

if "analysis_history" not in st.session_state:
    st.session_state.analysis_history = load_history()

with st.sidebar:
    st.header("🛡️ About ScamShield")
    st.write("ScamShield AI helps you review suspicious messages, inspect links, and choose safer next steps.")
    st.markdown("---")
    st.caption("How it works")
    st.write("It checks for common scam wording and basic URL warning signs. It does not verify a sender or website against live threat databases.")
    st.markdown("---")
    st.caption("Your history")
    st.write("Analysis history is saved locally in `analysis_history.json` on this computer.")

analyze_tab, url_tab, dashboard_tab, history_tab = st.tabs(["🔎 Analyze Message", "🔗 URL Checker", "📊 Dashboard", "🕘 Analysis History"])

with analyze_tab:
    left, right = st.columns([1.5, 1])
    with left:
        st.subheader("Analyze a message")
        sample = st.selectbox("Try a sample", [
            "Choose a sample...",
            "URGENT! Your bank account will be blocked. Verify your account and share your OTP immediately.",
            "Congratulations! You have won a free gift. Pay a processing fee now to claim your prize.",
            "Hi, our meeting is at 3 PM. Please bring the project notes.",
            "Work from home and earn guaranteed returns. Transfer money to activate your account.",
        ])
        default_text = "" if sample == "Choose a sample..." else sample
        message = st.text_area("Paste the SMS, email, chat message, or suspicious link here", value=default_text, height=190, placeholder="Paste the message here...")
        analyze = st.button("🔍 Analyze message", type="primary", use_container_width=True)

    with right:
        st.subheader("What this checks")
        st.markdown("""
        <div class="info-card">
          <h3>🔎 Common warning signs</h3>
          <p>⏰ Pressure or urgent threats</p>
          <p>💸 Requests for money or fees</p>
          <p>🔐 OTP, PIN, password, or bank-detail requests</p>
          <p>🎁 Prize claims and suspicious job or investment wording</p>
          <p>🔗 Basic URL warning signs</p>
        </div>
        <p class="small-note">A warning is a reason to verify—not proof that something is a scam.</p>
        """, unsafe_allow_html=True)

    if analyze:
        if not message.strip():
            st.warning("Please paste a message or link first.")
        else:
            verdict, score, matches, urls = analyze_message(message)
            record = {
                "timestamp": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
                "message": message.strip(), "verdict": verdict, "score": score,
                "signals": matches, "urls": urls,
            }
            st.session_state.analysis_history.insert(0, record)
            st.session_state.analysis_history = st.session_state.analysis_history[:500]
            save_history(st.session_state.analysis_history)
            st.session_state.latest_result = record

    result = st.session_state.get("latest_result")
    if result:
        st.markdown("---")
        st.subheader("Latest analysis result")
        col1, col2, col3 = st.columns(3)
        col1.metric("Risk estimate", f"{result['score']}/100")
        col2.metric("Assessment", result["verdict"])
        col3.metric("Signals found", len(result["signals"]))
        st.caption("Illustrative risk score — this is not a verified probability of fraud.")
        st.progress(int(result["score"]), text=f"Risk indicator: {result['score']} / 100")
        if result["verdict"] == "High risk":
            st.error("Potential scam signs detected. Do not click links or send money until you verify independently.")
        elif result["verdict"] == "Caution":
            st.warning("Some warning signs were detected. Verify the sender through an official channel.")
        else:
            st.success("Few known warning signs were detected. This does not prove the message is safe.")
        st.write("**Signals found**")
        if result["signals"]:
            for item in result["signals"]:
                st.write(f"- {item}")
        else:
            st.write("No listed scam phrases were detected.")
        if result["urls"]:
            st.write("**Links found**")
            for item in result["urls"]:
                st.code(item["url"])
                if item["reasons"]:
                    for reason in item["reasons"]:
                        st.write(f"- ⚠️ {reason}")
                else:
                    st.write("- No basic URL warning sign detected. Still verify the domain carefully.")
        st.info("Recommended action: do not reply, click, pay, or share sensitive information. Contact the organization using a phone number or website you find independently.")


with url_tab:
    st.subheader("🔗 Check a suspicious link")
    st.write("Paste a URL or domain to inspect visible warning signs before opening it.")
    st.warning("This checker does not open the link or query live threat databases. A low warning score does not mean a link is safe.")
    with st.form("url_checker_form"):
        url_input = st.text_input("Website URL", placeholder="https://example.com/login")
        check_url = st.form_submit_button("🔍 Check URL", type="primary", use_container_width=True)
    if check_url:
        if not url_input.strip():
            st.warning("Please enter a URL or domain first.")
        else:
            url_result = inspect_url(url_input)
            st.markdown("#### URL inspection result")
            st.code(url_result["url"])
            score = url_result["score"]
            risk_label = "High warning signs" if score >= 45 else "Some warning signs" if score >= 15 else "Few visible warning signs"
            c1, c2 = st.columns(2)
            c1.metric("Warning score", f"{score}/100")
            c2.metric("Assessment", risk_label)
            st.progress(score, text=f"Visible warning indicator: {score}/100")
            if not url_result["valid"]:
                st.error("The URL could not be confidently parsed. Check that it is typed correctly.")
            elif score >= 45:
                st.error("Several visible warning signs were found. Do not open it unless you verify the destination independently.")
            elif score >= 15:
                st.warning("Some visible warning signs were found. Check the domain carefully using an official source.")
            else:
                st.success("Few basic warning signs were found. This does not prove the website is legitimate or safe.")
            if url_result["reasons"]:
                st.write("**Warning signs**")
                for reason in url_result["reasons"]:
                    st.write(f"- ⚠️ {reason}")
            else:
                st.write("No basic warning signs were detected by these simple checks.")
            st.info("Safety tip: do not enter passwords, OTPs, payment details, or personal information through a link in an unexpected message. Find the organisation's official website independently.")


with dashboard_tab:
    st.subheader("📊 Scam analysis dashboard")
    history = st.session_state.analysis_history
    if not history:
        st.info("No analyses yet. Open the Analyze Message tab and analyze a message to populate your dashboard.")
    else:
        total = len(history)
        high = sum(item.get("verdict") == "High risk" for item in history)
        caution = sum(item.get("verdict") == "Caution" for item in history)
        lower = sum(item.get("verdict") == "Lower risk" for item in history)
        average = round(sum(int(item.get("score", 0)) for item in history) / total, 1)
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total analyses", total)
        c2.metric("High risk", high)
        c3.metric("Caution", caution)
        c4.metric("Average risk score", f"{average}/100")
        st.markdown("#### Risk-level distribution")
        distribution = pd.DataFrame({"Risk level": ["High risk", "Caution", "Lower risk"], "Analyses": [high, caution, lower]})
        st.bar_chart(distribution.set_index("Risk level"))
        st.markdown("#### Recent activity")
        activity = pd.DataFrame([{
            "Time": item.get("timestamp", ""), "Risk level": item.get("verdict", ""),
            "Score": item.get("score", 0), "Message preview": item.get("message", "").replace("\n", " ")[:90],
        } for item in history[:10]])
        st.dataframe(activity, use_container_width=True, hide_index=True)

with history_tab:
    st.subheader("🕘 Analysis history")
    history = st.session_state.analysis_history
    if not history:
        st.info("Your analysis history is empty. Analyze a message first.")
    else:
        risk_filter = st.selectbox("Filter by risk level", ["All", "High risk", "Caution", "Lower risk"])
        filtered = history if risk_filter == "All" else [item for item in history if item.get("verdict") == risk_filter]
        st.caption(f"Showing {len(filtered)} of {len(history)} saved analyses")
        for item in filtered:
            title = f"{item.get('timestamp', 'Unknown time')} · {item.get('verdict', 'Unknown')} · {item.get('score', 0)}/100"
            with st.expander(title):
                st.write("**Message**")
                st.text(item.get("message", ""))
                st.write("**Signals**")
                signals = item.get("signals", [])
                st.write(", ".join(signals) if signals else "No listed signals")
                for url in item.get("urls", []):
                    st.code(url.get("url", ""))
                    for reason in url.get("reasons", []):
                        st.write(f"- ⚠️ {reason}")
        export_rows = [{
            "timestamp": item.get("timestamp", ""), "verdict": item.get("verdict", ""),
            "score": item.get("score", 0), "message": item.get("message", ""),
            "signals": "; ".join(item.get("signals", [])),
        } for item in filtered]
        export_df = pd.DataFrame(export_rows, columns=["timestamp", "verdict", "score", "message", "signals"])
        st.download_button("⬇️ Download visible history as CSV", export_df.to_csv(index=False).encode("utf-8-sig"), "scamshield_history.csv", "text/csv")
        if st.button("🗑️ Clear all analysis history", type="secondary"):
            st.session_state.analysis_history = []
            st.session_state.pop("latest_result", None)
            save_history([])
            st.success("Analysis history cleared.")
            st.rerun()

st.markdown("---")
st.caption("ScamShield AI is a demonstration prototype. It does not query live threat-intelligence databases and may miss scams or flag legitimate messages. A low-risk result does not guarantee safety.")
