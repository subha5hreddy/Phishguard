import streamlit as st
import pandas as pd
from phishguard.analyzer import PhishGuardAnalyzer
from phishguard.reporter import PhishGuardReporter

st.set_page_config(
    page_title="PhishGuard – Advanced Phishing URL Detection System",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ PhishGuard")
st.markdown("### Advanced Phishing URL Detection & Explainable Threat Analysis System")

# Sidebar
st.sidebar.header("Navigation & Settings")
app_mode = st.sidebar.selectbox("Choose Mode", ["Single URL Analysis", "Batch CSV Scanner", "About PhishGuard"])

if app_mode == "Single URL Analysis":
    st.markdown("Enter a suspicious URL below to evaluate its threat score, examine heuristic findings, and review explainable security indicators.")
    
    url_input = st.text_input("Target URL", placeholder="https://example.com/login")
    
    if st.button("Analyze URL", type="primary"):
        if not url_input.strip():
            st.warning("Please enter a valid URL.")
        else:
            with st.spinner("Analyzing URL heuristics and threat vectors..."):
                analyzer = PhishGuardAnalyzer(url_input)
                report = analyzer.analyze()
            
            st.markdown("---")
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric(label="Risk Score (0-100)", value=f"{report['risk_score']} / 100")
            with col2:
                risk_color = {
                    "Low": "🟢",
                    "Medium": "🟡",
                    "High": "🔴",
                    "Critical": "🚨"
                }
                level = report['risk_level']
                st.metric(label="Threat Classification", value=f"{risk_color.get(level, '🔴')} {level}")
            with col3:
                st.metric(label="Total Findings", value=len(report['findings']))

            st.markdown("#### Normalized URL")
            st.code(report['normalized_url'])

            st.markdown("#### Explainable Detection Findings")
            for finding in report['findings']:
                status = finding['status']
                badge = "✅" if status == "Passed" else ("⚠️" if status in ["Warning", "Suspicious"] else "🚨")
                with st.expander(f"{badge} [{finding['check']}] - Status: {status} (Weight: +{finding['weight']})"):
                    st.write(finding['detail'])

            st.markdown("#### Export Report")
            if st.button("Export Report as JSON"):
                fname = PhishGuardReporter.export_json([report])
                st.success(f"Report exported successfully to {fname}!")

elif app_mode == "Batch CSV Scanner":
    st.markdown("Upload a CSV file containing a column named `url` to scan multiple URLs simultaneously.")
    uploaded_file = st.file_uploader("Upload CSV", type=["csv"])
    
    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)
        if 'url' not in df.columns:
            st.error("Uploaded CSV must contain a column named `url`.")
        else:
            if st.button("Run Batch Scan", type="primary"):
                results = []
                progress_bar = st.progress(0)
                total = len(df)
                
                for idx, row in df.iterrows():
                    analyzer = PhishGuardAnalyzer(str(row['url']))
                    results.append(analyzer.analyze())
                    progress_bar.progress((idx + 1) / total)
                
                res_df = pd.DataFrame(results)
                st.success("Batch scan completed!")
                st.dataframe(res_df[['raw_url', 'risk_score', 'risk_level']])
                
                csv_data = res_df.to_csv(index=False).encode('utf-8')
                st.download_button("Download Scan Results CSV", data=csv_data, file_name="phishguard_batch_report.csv", mime="text/csv")

else:
    st.markdown("### About PhishGuard")
    st.write("PhishGuard is a modular, weighted-risk phishing URL detection system designed for security analysts, automated threat intelligence pipelines, and end-user verification.")
    st.markdown("#### Core Features:")
    st.markdown("- **URL validation and normalization**")
    st.markdown("- **IP address and domain analysis**")
    st.markdown("- **Typosquatting & brand impersonation detection**")
    st.markdown("- **Suspicious keyword & obfuscation checks (@ symbol, long paths)**")
    st.markdown("- **Weighted risk scoring (0-100) & risk classification (Low, Medium, High, Critical)**")
    st.markdown("- **Explainable detection results with detailed justifications**")
    st.markdown("- **CSV and JSON export capabilities**")
    st.markdown("- **Interactive Web Dashboard built with Streamlit**")
