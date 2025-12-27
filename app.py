import streamlit as st
import pandas as pd
import time
from AKLGuard import AKLGuard


st.set_page_config(
    page_title="AKLGuard - Forensic Analyzer",
    page_icon="🛡️",
    layout="wide"
)


if 'guard' not in st.session_state:
    st.session_state.guard = AKLGuard(types="fast")
if 'full_df' not in st.session_state:
    st.session_state.full_df = pd.DataFrame()


st.sidebar.header("🛡️ Control Panel")

scan_mode = st.sidebar.toggle("Deep Scan (Slow Mode)", value=False)
mode_type = "slow" if scan_mode else "fast"

if st.sidebar.button("🚀 RUN ANALYSIS", use_container_width=True):
    with st.spinner(f"Analyzing system in {mode_type} mode..."):
        try:
            st.session_state.guard.types = mode_type
            st.session_state.guard.update_df()
            st.session_state.guard.risk_score()
            st.session_state.full_df = st.session_state.guard.snapshot_df.copy()
            st.success(f"Analysis Complete at {time.strftime('%H:%M:%S')}")
        except Exception as e:
            st.error(f"Error: {e}")


st.title("🛡️ AKLGuard Forensic Monitor")
st.markdown("---")

col1, col2, col3, col4 = st.columns([2, 1, 1, 1])

with col1:
    search_query = st.text_input("🔍 Search PIDs, Names, or IPs...", placeholder="Type to filter...")

with col2:
    net_filter = st.checkbox("🌐 Using Network")

with col3:
    hidden_filter = st.checkbox("👻 Hidden (No Window)")

with col4:
    suspicious_only = st.checkbox("🚨 Suspicious Only", value=False)


df = st.session_state.full_df.copy()

if not df.empty:
 
    if search_query:
        df = df[df.astype(str).apply(lambda x: x.str.contains(search_query, case=False)).any(axis=1)]

 
    if net_filter:
        df = df[df['net_use'] == True]


    if hidden_filter:
        df = df[df['HasWindow'] == False]

 
    if suspicious_only:
        df = df[df['Suspicious'] == True]


    def highlight_suspicious(row):
        
        return ['background-color: #4A1010; color: #FFC3C3' if row.get('Suspicious', False) else '' for _ in row]


    styled_df = df.style.apply(highlight_suspicious, axis=1)


    c1, c2, c3 = st.columns(3)
    c1.metric("Total Processes", len(df))
    c2.metric("Suspicious Found", len(df[df['Suspicious'] == True]), delta_color="inverse")
    c3.metric("Network Connections", len(df[df['net_use'] == True]))


    st.dataframe(
        styled_df,
        use_container_width=True,
        height=600,
        column_config={
            "Suspicious": st.column_config.CheckboxColumn("🚨 Suspicious"),
            "net_use": st.column_config.CheckboxColumn("🌐 Net"),
            "HasWindow": st.column_config.CheckboxColumn("🪟 Win")
        }
    )
    

    csv = df.to_csv(index=False).encode('utf-8')
    st.download_button("📥 Export Report as CSV", csv, "forensic_report.csv", "text/csv")

else:
    st.info("👋 Welcome! Click 'RUN ANALYSIS' in the sidebar to start monitoring.")


st.markdown("---")
st.caption("AKLGuard Security Analyzer | Streamlit Edition")