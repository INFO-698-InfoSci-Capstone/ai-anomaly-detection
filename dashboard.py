import streamlit as st
import pandas as pd
import plotly.express as px
import sqlite3
import time

# Set page configuration for a better layout
st.set_page_config(page_title="Cyber Threat Detection Dashboard", layout="wide")

# Custom CSS for styling
st.markdown("""
    <style>
    .main-title {
        color: #2c3e50;
        font-size: 36px;
        font-weight: bold;
        text-align: center;
        margin-bottom: 20px;
    }
    .subheader {
        color: #34495e;
        font-size: 24px;
        font-weight: bold;
        margin-top: 20px;
    }
    .stDataFrame {
        border-radius: 10px;
        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    }
    .stMetric {
        background-color: #f8f9fa;
        border-radius: 10px;
        padding: 10px;
        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    }
    .stSidebar .sidebar-content {
        background-color: #f8f9fa;
    }
    </style>
""", unsafe_allow_html=True)

# Title
st.markdown('<div class="main-title">Cyber Threat Detection Dashboard</div>', unsafe_allow_html=True)

# Initialize session state for chart filters
if 'selected_threat_type' not in st.session_state:
    st.session_state.selected_threat_type = None
if 'selected_date' not in st.session_state:
    st.session_state.selected_date = None

# Function to load logs from SQLite database
def load_logs_from_db():
    try:
        conn = sqlite3.connect("logs.db")
        query = "SELECT timestamp, source_ip, destination_ip, protocol, anomaly_score, predicted_traffic_type, risk_flag, confidence_score, log_id FROM logs ORDER BY timestamp DESC"
        df = pd.read_sql_query(query, conn)
        conn.close()
        print(f"Loaded {len(df)} logs from database")
        if not df.empty:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            # Clean predicted_traffic_type by removing brackets
            df['predicted_traffic_type'] = df['predicted_traffic_type'].str.strip("[']").str.strip("']")
            print(f"Sample log: {df.iloc[0].to_dict()}")
            print(f"Risk flags in database: {df['risk_flag'].unique()}")
            print(f"Threat types in database: {df['predicted_traffic_type'].unique()}")
            print(f"Protocols in database: {df['protocol'].unique()}")
            print(f"Timestamp range in database: {df['timestamp'].min()} to {df['timestamp'].max()}")
        return df
    except Exception as e:
        print(f"Error loading logs from database: {e}")
        st.warning(f"Error loading logs from database: {e}")
        return pd.DataFrame()

# Sidebar for filters
st.sidebar.header("Filter Options")
risk_filter = st.sidebar.multiselect(
    "Select Risk Levels",
    options=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
    default=["LOW", "MEDIUM", "HIGH", "CRITICAL"]
)
threat_filter = st.sidebar.multiselect(
    "Select Threat Types",
    options=["Normal", "Data Exfiltration", "Brute Force", "Phishing", "DDoS", "Scanning"],
    default=["Normal", "Data Exfiltration", "Brute Force", "Phishing", "DDoS", "Scanning"]
)
protocol_filter = st.sidebar.multiselect(
    "Select Protocols",
    options=["TCP", "UDP", "ICMP", "FTP", "DNS", "HTTP", "SMTP", "SSH", "HTTPS"],
    default=["TCP", "UDP", "ICMP", "FTP", "DNS", "HTTP", "SMTP", "SSH", "HTTPS"]
)
source_ip_filter = st.sidebar.text_input("Filter by Source IP (e.g., 10.249.217.134)")
date_range = st.sidebar.date_input(
    "Select Date Range",
    value=(pd.Timestamp('2025-03-01'), pd.Timestamp('2025-04-30')),
    min_value=pd.Timestamp('2025-03-01'),
    max_value=pd.Timestamp('2025-04-30')
)

# Add reset button for chart filters
if st.session_state.selected_threat_type or st.session_state.selected_date:
    if st.sidebar.button("Reset Chart Filters"):
        st.session_state.selected_threat_type = None
        st.session_state.selected_date = None
        st.rerun()

# Display current chart-based filters
st.sidebar.subheader("Current Chart Filters")
st.sidebar.write(f"**Threat Type**: {st.session_state.selected_threat_type if st.session_state.selected_threat_type else 'None'}")
st.sidebar.write(f"**Date**: {st.session_state.selected_date if st.session_state.selected_date else 'None'}")

# Placeholders for dynamically updated sections
summary_placeholder = st.empty()
threat_dist_placeholder = st.empty()
anomaly_scores_placeholder = st.empty()
risk_level_dist_placeholder = st.empty()
recent_logs_placeholder = st.empty()
high_risk_placeholder = st.empty()
download_button_placeholder = st.empty()

# Main loop for continuous updates of all sections
last_row_count = 0
iteration = 0
while True:
    df = load_logs_from_db()
    
    if not df.empty:
        # Apply filters
        filtered_df = df[df["risk_flag"].isin(risk_filter) & df["predicted_traffic_type"].isin(threat_filter) & df["protocol"].isin(protocol_filter)]
        if source_ip_filter:
            filtered_df = filtered_df[filtered_df["source_ip"].str.contains(source_ip_filter, case=False, na=False)]
        if len(date_range) == 2:
            start_date, end_date = date_range
            filtered_df = filtered_df[
                (filtered_df['timestamp'] >= pd.to_datetime(start_date)) &
                (filtered_df['timestamp'] <= pd.to_datetime(end_date) + pd.Timedelta(days=1))
            ]
        # Apply chart-based filters
        if st.session_state.selected_threat_type:
            filtered_df = filtered_df[filtered_df["predicted_traffic_type"] == st.session_state.selected_threat_type]
        if st.session_state.selected_date:
            filtered_df = filtered_df[filtered_df["timestamp"].dt.date == st.session_state.selected_date]
        print(f"After filtering: {len(filtered_df)} logs")

        # Aggregate anomaly scores by day for the scatter plot
        df_agg = filtered_df.groupby(pd.Grouper(key='timestamp', freq='D'))['anomaly_score'].mean().reset_index()
        df_agg['Anomaly_Score_Smoothed'] = df_agg['anomaly_score'].rolling(window=3, min_periods=1).mean()

        # Summary Metrics
        with summary_placeholder.container():
            st.markdown('<div class="subheader">Summary</div>', unsafe_allow_html=True)
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric(label="Total Logs Processed", value=len(filtered_df), delta_color="off")
            with col2:
                high_risk_count = len(filtered_df[filtered_df["risk_flag"].isin(["CRITICAL", "HIGH"])])
                st.metric(label="High-Risk Alerts", value=high_risk_count, delta_color="off")
            with col3:
                st.metric(label="Unique Threat Types", value=len(filtered_df["predicted_traffic_type"].unique()), delta_color="off")

        # Combine Threat Type Distribution and Risk Level Distribution in a two-column layout
        col1, col2 = st.columns(2)

        # Threat Type Distribution (Left Column)
        with col1:
            with threat_dist_placeholder.container():
                st.markdown('<div class="subheader">Threat Type Distribution</div>', unsafe_allow_html=True)
                if not filtered_df.empty:
                    threat_counts = filtered_df["predicted_traffic_type"].value_counts().reset_index()
                    threat_counts.columns = ["Threat Type", "Count"]
                    fig = px.bar(
                        threat_counts,
                        x="Threat Type",
                        y="Count",
                        labels={"Threat Type": "Threat Type", "Count": "Count"},
                        color="Threat Type",
                        color_discrete_sequence=px.colors.qualitative.Pastel
                    )
                    fig.update_layout(
                        showlegend=False,
                        plot_bgcolor="white",
                        paper_bgcolor="white",
                        font=dict(size=12),
                        margin=dict(l=20, r=20, t=20, b=20),
                        height=350
                    )
                    fig.update_traces(marker_line_width=0)
                    # Capture click events
                    selected_threat = st.plotly_chart(fig, use_container_width=True, key=f"threat_type_distribution_{iteration}", on_select="rerun")
                    if selected_threat and selected_threat.get("points"):
                        st.session_state.selected_threat_type = selected_threat["points"][0]["x"]
                else:
                    st.warning("No data available for Threat Type Distribution")

        # Risk Level Distribution (Right Column)
        with col2:
            with risk_level_dist_placeholder.container():
                st.markdown('<div class="subheader">Risk Level Distribution</div>', unsafe_allow_html=True)
                if not filtered_df.empty:
                    risk_counts = filtered_df["risk_flag"].value_counts().reset_index()
                    risk_counts.columns = ["risk_flag", "count"]
                    fig = px.pie(
                        risk_counts,
                        names="risk_flag",
                        values="count",
                        color="risk_flag",
                        color_discrete_map={
                            "LOW": "#2ECC71",      # Medium-dark green
                            "MEDIUM": "#F1C40F",   # Yellowish-orange
                            "HIGH": "#E74C3C",     # Lighter red
                            "CRITICAL": "#C0392B"  # Darker red
                        }
                    )
                    fig.update_layout(
                        plot_bgcolor="white",
                        paper_bgcolor="white",
                        font=dict(size=12, color="#333333"),
                        margin=dict(l=20, r=20, t=20, b=20),
                        height=350
                    )
                    fig.update_traces(textinfo="percent+label", textfont=dict(color="#333333"))
                    st.plotly_chart(fig, use_container_width=True, key=f"risk_level_distribution_{iteration}")
                else:
                    st.warning("No data available for Risk Level Distribution")

        # Anomaly Scores Over Time
        with anomaly_scores_placeholder.container():
            st.markdown('<div class="subheader">Anomaly Scores Over Time</div>', unsafe_allow_html=True)
            if not df_agg.empty:
                fig = px.scatter(
                    df_agg,
                    x="timestamp",
                    y="anomaly_score",
                    trendline="lowess",
                    color="anomaly_score",
                    color_continuous_scale=["#0000ff", "#00ff00", "#ff0000"],
                    labels={"anomaly_score": "Anomaly Score"}
                )
                fig.update_traces(
                    marker=dict(size=8, opacity=0.6),
                    line=dict(color="#1f77b4", width=2)
                )
                fig.update_layout(
                    xaxis_title="Timestamp",
                    yaxis_title="Anomaly Score",
                    plot_bgcolor="white",
                    paper_bgcolor="white",
                    font=dict(size=12, color="#333333"),
                    margin=dict(l=50, r=50, t=50, b=50),
                    height=400,
                    xaxis_tickangle=45,
                    showlegend=False,
                    yaxis_showgrid=True,
                    yaxis_gridcolor="lightgray",
                    yaxis_gridwidth=1,
                    xaxis_showgrid=True,
                    xaxis_gridcolor="lightgray",
                    xaxis_title_font_color="#333333",
                    yaxis_title_font_color="#333333",
                    xaxis_tickfont_color="#333333",
                    yaxis_tickfont_color="#333333"
                )
                # Capture click events
                selected_point = st.plotly_chart(fig, use_container_width=True, key=f"anomaly_scores_over_time_{iteration}", on_select="rerun")
                if selected_point and selected_point.get("points"):
                    selected_timestamp = pd.to_datetime(selected_point["points"][0]["x"]).date()
                    st.session_state.selected_date = selected_timestamp
            else:
                st.warning("No data available for Anomaly Scores Over Time")

        # Layout with columns for Recent Logs
        col1, col2 = st.columns([3, 2])

        # Recent Logs
        with col1:
            with recent_logs_placeholder.container():
                st.markdown('<div class="subheader">Recent Logs</div>', unsafe_allow_html=True)
                if not filtered_df.empty:
                    filtered_df['Risk_Display'] = filtered_df['risk_flag'].apply(
                        lambda x: f"🟢 {x}" if x == "LOW" else f"🟠 {x}" if x == "MEDIUM" else f"🟡 {x}" if x == "HIGH" else f"🔴 {x}"
                    )
                    filtered_df['Confidence_Display'] = filtered_df['confidence_score'].apply(lambda x: f"Confidence: {x:.2%}")
                    st.dataframe(
                        filtered_df.tail(10),
                        use_container_width=True,
                        column_config={
                            "timestamp": st.column_config.DatetimeColumn(format="YYYY-MM-DD HH:mm:ss", label="Timestamp"),
                            "source_ip": st.column_config.TextColumn(label="Source IP"),
                            "destination_ip": st.column_config.TextColumn(label="Destination IP"),
                            "anomaly_score": st.column_config.NumberColumn(format="%.4f", label="Anomaly Score"),
                            "Risk_Display": st.column_config.TextColumn(label="Risk Level"),
                            "Confidence_Display": st.column_config.TextColumn(label="Confidence", help="Prediction confidence from CatBoost"),
                            "confidence_score": None,
                            "risk_flag": None,
                            "log_id": None
                        },
                        column_order=["timestamp", "source_ip", "destination_ip", "protocol", "anomaly_score", "predicted_traffic_type", "Risk_Display", "Confidence_Display"]
                    )
                else:
                    st.warning("No recent logs available")

        # High-Risk Alerts with Download Button
        with high_risk_placeholder.container():
            st.markdown('<div class="subheader">Critical & High-Risk Alerts</div>', unsafe_allow_html=True)
            high_risk = filtered_df[filtered_df["risk_flag"].isin(["CRITICAL", "HIGH"])]
            if not high_risk.empty:
                high_risk['Risk_Display'] = high_risk['risk_flag'].apply(
                    lambda x: f"🟡 {x}" if x == "HIGH" else f"🔴 {x}"
                )
                high_risk['Confidence_Display'] = high_risk['confidence_score'].apply(lambda x: f"Confidence: {x:.2%}")
                st.dataframe(
                    high_risk,
                    use_container_width=True,
                    column_config={
                        "timestamp": st.column_config.DatetimeColumn(format="YYYY-MM-DD HH:mm:ss", label="Timestamp"),
                        "source_ip": st.column_config.TextColumn(label="Source IP"),
                        "destination_ip": st.column_config.TextColumn(label="Destination IP"),
                        "anomaly_score": st.column_config.NumberColumn(format="%.4f", label="Anomaly Score"),
                        "Risk_Display": st.column_config.TextColumn(label="Risk Level"),
                        "Confidence_Display": st.column_config.TextColumn(label="Confidence", help="Prediction confidence from CatBoost"),
                        "confidence_score": None,
                        "risk_flag": None,
                        "log_id": None
                    },
                    hide_index=True,
                    column_order=["timestamp", "source_ip", "destination_ip", "protocol", "anomaly_score", "predicted_traffic_type", "Risk_Display", "Confidence_Display"]
                )
            else:
                st.warning("No Critical or High-Risk Alerts Found")

        # Download Button
        with download_button_placeholder.container():
            if not high_risk.empty:
                csv = high_risk.to_csv(index=False)
                st.download_button(
                    label="Download High-Risk Alerts as CSV",
                    data=csv,
                    file_name="high_risk_alerts.csv",
                    mime="text/csv",
                    key=f"download_high_risk_alerts_{iteration}_{int(time.time())}"
                )

    # Increment iteration counter
    iteration += 1

    # Wait before the next refresh
    time.sleep(5)