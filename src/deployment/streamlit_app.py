import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
from src.agent.email_agent import get_latest_emails
from src.agent.utils import get_gmail_service
from src.deployment.detect_email import EmailPhishingDetector

# 1. Page Configuration & Theme
st.set_page_config(page_title="PhishGuard SOC Console", layout="wide", initial_sidebar_state="expanded")

# 2. Professional SOC CSS Styling
st.markdown("""
    <style>
    .status-legit { color: #00cc96; font-weight: bold; border: 1px solid #00cc96; padding: 2px 8px; border-radius: 4px; }
    .status-phish { color: #ff4b4b; font-weight: bold; border: 1px solid #ff4b4b; padding: 2px 8px; border-radius: 4px; }
    .sev-critical { color: #8b0000; font-weight: bold; }
    .sev-high { color: #ff4b4b; font-weight: bold; }
    .sev-medium { color: #ffa500; font-weight: bold; }
    .sev-low { color: #00cc96; font-weight: bold; }
    .stMetric { background-color: #1e2130; padding: 15px; border-radius: 10px; border: 1px solid #31333f; }
    .email-body-container { 
        background-color: #ffffff; 
        color: #000000; 
        padding: 20px; 
        border-radius: 5px; 
        overflow-y: auto; 
        max-height: 500px; 
        border: 1px solid #ddd;
        font-family: Arial, sans-serif;
    }
    </style>
""", unsafe_allow_html=True)

# 3. Initialize Detector
detector = EmailPhishingDetector()

# 4. Sidebar Navigation
# Provides UI controls for fetching emails and selecting folders.
with st.sidebar:
    st.title("SOC Control Plane")
    st.markdown("---")
    view_mode = st.radio("Queue Selection", ["Inbox Analysis", "Spam Folder"])
    max_results = st.slider("Emails to fetch", 5, 50, 20)
    st.markdown("---")
    if st.button("Refresh Threat Feed", width="stretch"):
        st.rerun()

# 5. Session & Authentication
# Handles Google OAuth flow to ensure the app has permission to read the user's emails.
if "gmail_creds" not in st.session_state:
    st.session_state.gmail_creds = None

if st.session_state.gmail_creds is None:
    st.title("Authentication")
    if st.button("Authorize SOC Access"):
        try:
            st.session_state.gmail_creds = get_gmail_service()
            st.success("Access Granted.")
            st.rerun()
        except Exception as e:
            st.error(f"Auth Error: {e}")
    st.stop()

@st.cache_data(show_spinner=False)
def fetch_and_analyze_emails(_creds, label, max_results):
    """
    Fetches emails and runs the detector.predict() on each.
    Cached to prevent re-running analysis (and hitting API limits) on every UI toggle.
    """
    emails = get_latest_emails(_creds, max_results=max_results, label=label)
    processed = []
    for mail in emails:
        # This is the heavy lifting that causes timeouts
        analysis = detector.predict(mail["body"], mail["sender"], mail.get("reply_to", ""), mail["subject"])
        mail.update(analysis)
        processed.append(mail)
    return processed

# 6. Data Acquisition & Processing
label = "INBOX" if view_mode == "Inbox Analysis" else "SPAM"
with st.spinner(f"Analyzing {label} activity..."):
    # Use the cached function here
    processed_emails = fetch_and_analyze_emails(st.session_state.gmail_creds, label, max_results)

# 7. Dashboard Metrics
# Calculates top-level KPIs (Key Performance Indicators) for the dashboard header.
st.title("Threat Detection & Response")
phish_count = sum(1 for e in processed_emails if e["prediction"] == "PHISHING")
avg_risk = sum(e['risk_score'] for e in processed_emails)/len(processed_emails) if processed_emails else 0

m1, m2, m3, m4 = st.columns(4)
m1.metric("Total Scanned", len(processed_emails))
m2.metric("Detected Threats", phish_count, delta=f"{phish_count} High Risk", delta_color="inverse")
m3.metric("Avg Risk Score", f"{avg_risk:.2f}")
m4.metric("Active SOC Session", datetime.now().strftime("%H:%M:%S"))

st.divider()

# 8. Filter & Visualizations
# Uses Plotly to create interactive charts showing attack distribution.
severity_filter = st.selectbox("Filter Triage Queue by Severity", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"], index=0)

col_left, col_right = st.columns(2)

# Prepare Visualization Data
df_viz = pd.DataFrame([
    {
        "Severity": e["risk_level"],
        "Technique": t["name"] if e["threat_matrix"] else "None",
        "Score": e["risk_score"]
    } for e in processed_emails for t in (e["threat_matrix"] if e["threat_matrix"] else [{"name": "None"}])
])

with col_left:
    st.markdown("### Active Threats by Severity")
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    sev_counts = df_viz["Severity"].value_counts().reset_index()
    sev_counts.columns = ["Severity Level", "Incident Count"]
    
    fig_sev = px.bar(sev_counts, x="Severity Level", y="Incident Count", color="Severity Level",
                     category_orders={"Severity Level": severity_order},
                     color_discrete_map={"CRITICAL": "#8b0000", "HIGH": "#ff4b4b", "MEDIUM": "#ffa500", "LOW": "#00cc96"})
    fig_sev.update_layout(showlegend=False, height=300, margin=dict(t=10, b=10, l=10, r=10))
    st.plotly_chart(fig_sev, width="stretch")

with col_right:
    st.markdown("### Trending Attack Techniques")
    tech_counts = df_viz[df_viz["Technique"] != "None"]["Technique"].value_counts().reset_index()
    tech_counts.columns = ["Technique", "Count"]
    # Professional Modern Palette (Blues/Purples)
    fig_tech = px.pie(tech_counts, values="Count", names="Technique", hole=0.5,
                      color_discrete_sequence=px.colors.sequential.dense)
    fig_tech.update_layout(height=300, margin=dict(t=10, b=10, l=10, r=10))
    st.plotly_chart(fig_tech, width="stretch")

st.divider()

# 9. Detection Trends & IP Reputation
t_col1, t_col2 = st.columns([2, 1])
with t_col1:
    st.markdown("### Detection Trend")
    trend_df = pd.DataFrame({"Risk Score": [e["risk_score"] for e in processed_emails[::-1]]})
    st.line_chart(trend_df, color="#ff4b4b", height=200)

with t_col2:
    st.markdown("### IP/Domain Reputation")
    rep_data = []
    for e in processed_emails:
        rep_data.extend(e.get("flagged_entities", []))
    if rep_data:
        st.table(pd.DataFrame(rep_data).drop_duplicates())
    else:
        st.info("No active malicious observables flagged.")

st.divider()

# 10. Triage Queue with Severity Column
st.subheader("Incident Triage Queue")

# Added a column for "No." and adjusted ratios to fit Severity
# Ratios: [No, Score, Severity, Sender, Subject, Status, Action, Inspect]
h_cols = st.columns([0.4, 0.6, 1.0, 2.0, 3.5, 1.0, 1.2, 0.8])
h_cols[0].write("**No.**")
h_cols[1].write("**SCORE**")
h_cols[2].write("**SEVERITY**")
h_cols[3].write("**SENDER**")
h_cols[4].write("**SUBJECT**")
h_cols[5].write("**STATUS**")
h_cols[6].write("**ACTION**")
# h_cols[7] is for the Inspect button, left blank in header

# Apply Severity Filter
display_emails = processed_emails if severity_filter == "ALL" else [e for e in processed_emails if e["risk_level"] == severity_filter]

for idx, email in enumerate(display_emails):
    with st.container():
        st.markdown('<hr style="border:0.1px solid #31333f; margin: 5px 0;">', unsafe_allow_html=True)
        
        # Match the header ratios exactly
        c0, c1, c2, c3, c4, c5, c6, c7 = st.columns([0.4, 0.6, 1.0, 2.0, 3.5, 1.0, 1.2, 0.8])
        
        # No. Column
        c0.write(f"{idx + 1}")
        
        # Score Column
        c1.write(f"**{email['risk_score']}**")
        
        # Severity Column (Fixed: Mapping the risk_level to the CSS classes)
        sev = email['risk_level'].upper()
        sev_class = f"sev-{sev.lower()}"
        c2.markdown(f'<span class="{sev_class}">{sev}</span>', unsafe_allow_html=True)
        
        # Sender & Subject
        c3.write(email['sender'][:25])
        c4.write(email['subject'][:70])
        
        # Status
        if email['prediction'] == "PHISHING":
            c5.markdown('<span class="status-phish">PHISH</span>', unsafe_allow_html=True)
        else:
            c5.markdown('<span class="status-legit">LEGIT</span>', unsafe_allow_html=True)
            
        # Action Dropdown
        with c6:
            st.selectbox("Action", ["Select...", "Quarantine", "Delete", "Whitelist"], 
                         key=f"a_{email['id']}", label_visibility="collapsed")
        
        # Inspect Button
        with c7:
            inspect_clicked = st.button("Inspect", key=f"btn_{email['id']}", width="stretch")

        if inspect_clicked:
            st.markdown(f"""
                <div style="background-color: #1e2130; padding: 20px; border-radius: 10px; border: 1px solid #31333f; margin-top: 20px;">
                    <h3 style="margin: 0;">Analysis</h3>
                </div>
            """, unsafe_allow_html=True)

            f_col1, f_col2 = st.columns(2)
            
            with f_col1:
                st.markdown("#### VirusTotal Intelligence")
                if email.get("flagged_entities"):
                    for entity in email["flagged_entities"]:
                        st.error(f"**MALICIOUS:** {entity['value']} ({entity['hits']} hits)")
                else:
                    st.success("No malicious matches found.")

            with f_col2:
                st.markdown("#### MITRE ATT&CK Mapping")
                if email.get("threat_matrix"):
                    for threat in email["threat_matrix"]:
                        # NEW STYLE: Card-based layout with accent border
                        st.markdown(f"""
                            <div style="
                                background-color: #161b22; 
                                border: 1px solid #30363d; 
                                border-left: 5px solid #ff4b4b; 
                                padding: 12px; 
                                border-radius: 4px; 
                                margin-bottom: 10px;">
                                <div style="color: #8b949e; font-size: 0.75rem; font-weight: bold; text-transform: uppercase;">
                                    {threat.get('tech', 'Technique')}
                                </div>
                                <div style="color: #f0f6fc; font-size: 1rem; font-weight: bold; margin: 4px 0;">
                                    {threat['name']}
                                </div>
                                <div style="color: #8b949e; font-size: 0.85rem; line-height: 1.4;">
                                    {threat['desc']}
                                </div>
                            </div>
                        """, unsafe_allow_html=True)
                else:
                    st.info("No specific attack patterns detected.")

            st.divider()
            
            # Risk Breakdown & Body
            b_col1, b_col2 = st.columns([1, 2])
            with b_col1:
                st.markdown("#### Risk Model Verdict")
                score_pct = email['risk_score'] * 100
                st.markdown(f"""
                    <div style="background-color: #1e2130; padding: 20px; border-radius: 10px; border: 1px solid #31333f; text-align: center;">
                        <small>CONFIDENCE</small><br><span style="font-size: 24px; color: #ff4b4b; font-weight: bold;">{score_pct:.1f}%</span>
                    </div>
                """, unsafe_allow_html=True)
                
                details = email.get("analysis_details", {'text_risk':0, 'sender_risk':0, 'url_risk':0})
                st.progress(details['text_risk'], text=f"Linguistic: {details['text_risk']*100:.0f}%")
                st.progress(details['sender_risk'], text=f"Reputation: {details['sender_risk']*100:.0f}%")
                st.progress(details['url_risk'], text=f"URL Risk: {details['url_risk']*100:.0f}%")

            with b_col2:
                st.markdown("#### Full Email Body")
                st.text_area("Source Code", value=email['body'], height=300, disabled=True, key=f"src_{email['id']}")

            if st.button("Close Analysis", key=f"cls_{email['id']}", width="stretch"):
                st.rerun()