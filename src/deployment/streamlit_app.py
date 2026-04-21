import streamlit as st
import pandas as pd
from src.agent.email_agent import get_latest_emails
from src.agent.utils import get_gmail_service
from src.deployment.detect_email import EmailPhishingDetector

# 1. Page Configuration
st.set_page_config(page_title="PhishGuard SOC", layout="wide", initial_sidebar_state="expanded")

# 2. Professional CSS Styling
st.markdown("""
    <style>
    .status-legit { color: #00cc96; font-weight: bold; text-transform: uppercase; border: 1px solid #00cc96; padding: 2px 8px; border-radius: 4px; }
    .status-phish { color: #ff4b4b; font-weight: bold; text-transform: uppercase; border: 1px solid #ff4b4b; padding: 2px 8px; border-radius: 4px; }
    .stMetric { background-color: #1e2130; padding: 15px; border-radius: 10px; border: 1px solid #31333f; }
    .threat-card { padding: 10px; border-left: 5px solid #ff4b4b; background: #262730; margin-bottom: 10px; border-radius: 4px; }
    </style>
""", unsafe_allow_html=True)

# 3. Initialize Detector
detector = EmailPhishingDetector()

# 4. Sidebar Navigation
with st.sidebar:
    st.title("🛡️ PhishGuard SOC")
    st.markdown("---")
    view_mode = st.radio("Queue Selection", ["Inbox Analysis", "Spam Quarantine"])
    max_results = st.slider("Emails to fetch", 5, 20, 10)
    st.markdown("---")
    if st.button("🔄 Refresh Fleet Scan", use_container_width=True):
        st.rerun()

# 5. Authentication Logic
if "gmail_creds" not in st.session_state:
    st.session_state.gmail_creds = None

st.title("Threat Detection Console")

if st.session_state.gmail_creds is None:
    if st.button("Authorize SOC Access"):
        try:
            st.session_state.gmail_creds = get_gmail_service()
            st.success("Access Granted.")
            st.rerun()
        except Exception as e:
            st.error(f"Auth Error: {e}")
    st.stop()

# 6. Main Scan Execution
label = "INBOX" if view_mode == "Inbox Analysis" else "SPAM"
with st.spinner(f"Scanning {label}..."):
    emails = get_latest_emails(st.session_state.gmail_creds, max_results=max_results, label=label)

# 7. Dashboard Metrics
processed_emails = []
for mail in emails:
    analysis = detector.predict(mail["body"], mail["sender"], mail.get("reply_to", ""), mail["subject"])
    mail.update(analysis)
    processed_emails.append(mail)

phish_count = sum(1 for e in processed_emails if e["prediction"] == "PHISHING")
col1, col2, col3 = st.columns(3)
col1.metric("Analyzed", len(processed_emails))
col2.metric("Threats", phish_count, delta=f"{phish_count} High Risk", delta_color="inverse")
col4_score = sum(e['risk_score'] for e in processed_emails)/len(processed_emails) if processed_emails else 0
col3.metric("Avg Risk", f"{col4_score:.2f}")

st.divider()

# 8. Professional Table Header
cols = st.columns([1, 2, 4, 1.5, 1.5])
cols[0].write("**SCORE**")
cols[1].write("**SENDER**")
cols[2].write("**SUBJECT**")
cols[3].write("**STATUS**")
cols[4].write("**ACTION**")
st.divider()

# 9. Professional Row Rendering (Refined SOC Version)
for email in processed_emails:
    # Use a stylized container to create a "Card" feel for each email
    with st.container():
        # Visual Divider
        st.markdown('<hr style="border:0.5px solid #31333f; margin-bottom:20px;">', unsafe_allow_html=True)
        
        # Row Header
        c1, c2, c3, c4, c5, c6 = st.columns([0.8, 2, 4, 1.2, 1.2, 1.2])
        
        c1.write(f"**{email['risk_score']}**")
        sender_name = email['sender'].split('<')[0].strip()[:25]
        c2.write(sender_name if sender_name else email['sender'][:25])
        c3.write(email['subject'][:75])
        
        # Status Label
        if email['prediction'] == "PHISHING":
            c4.markdown('<span class="status-phish">PHISHING</span>', unsafe_allow_html=True)
        else:
            c4.markdown('<span class="status-legit">LEGITIMATE</span>', unsafe_allow_html=True)
            
        # Action Dropdown
        with c5:
            action = st.selectbox("Action", 
                                ["Select...", "Mark as Safe", "Move to Inbox", "Delete", "Mark as Spam", "Flag for Retraining"], 
                                key=f"act_{email['id']}", label_visibility="collapsed")
        
        # Inspection Toggle
        with c6:
            inspect_clicked = st.button("Inspect", key=f"btn_{email['id']}", use_container_width=True)

        # Content revealed ONLY when Inspect is clicked
        if inspect_clicked:
            st.markdown("---")
            
            # --- SECTION 1: MITRE ATT&CK MATRIX (CLEANER) ---
            st.markdown("#### Incident Analysis Report")
            st.caption("Adversarial Tactics & Techniques Identification")
            
            if not email["threat_matrix"]:
                st.info("No adversarial techniques mapped via heuristic analysis.")
            else:
                # Use columns to prevent cards from being too wide
                t_cols = st.columns(3) 
                for i, indicator in enumerate(email["threat_matrix"]):
                    with t_cols[i % 3]:
                        # A compact, formal MITRE card
                        st.markdown(f"""
                            <div style="background-color: #3b1919; padding: 10px; border-radius: 5px; border-left: 5px solid #ff4b4b;">
                                <span style="font-size: 0.8rem; color: #ff4b4b; font-weight: bold;">{indicator['tech']}</span><br>
                                <span style="font-weight: bold; font-size: 0.9rem;">{indicator['name']}</span><br>
                                <p style="font-size: 0.75rem; margin: 0;">{indicator['desc']}</p>
                            </div>
                        """, unsafe_allow_html=True)

            st.markdown('<div style="margin-top: 20px;"></div>', unsafe_allow_html=True)

            # --- SECTION 2: ML METRIC BOX & EMAIL CONTENT ---
            col_left, col_right = st.columns([1, 2])
            
            with col_left:
                st.markdown("**ML Model Verdict**")
                # Confidence placed in a high-visibility stylized box
                st.markdown(f"""
                    <div style="border: 1px solid #31333f; padding: 20px; border-radius: 10px; background-color: #1e2130; text-align: center;">
                        <span style="font-size: 0.8rem; color: #888;">ENSEMBLE CONFIDENCE</span><br>
                        <span style="font-size: 2.2rem; font-weight: bold; color: #00cc96;">{email['analysis_details']['text_risk'] * 100:.1f}%</span><br>
                        <span style="font-size: 0.7rem; color: #555;">TF-IDF + Random Forest / XGBoost</span>
                    </div>
                """, unsafe_allow_html=True)
                st.caption("The model calculates this score based on linguistic patterns and historical phishing data.")

            with col_right:
                st.markdown("**Email Content**")
                st.text_area("Read-Only Export", value=email['body'], height=180, disabled=True, key=f"body_{email['id']}")

            st.markdown("---")
        # Clear spacing before next card
        st.markdown('<div style="margin-bottom: 30px;"></div>', unsafe_allow_html=True)