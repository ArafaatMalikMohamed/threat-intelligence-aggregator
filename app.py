import streamlit as st
import re
import ipaddress
import json
from collections import defaultdict
from datetime import datetime

st.set_page_config(page_title="Threat Intelligence Aggregator", layout="wide")
st.title("🛡️ Practical Threat Intelligence (TI) Aggregator")
st.markdown("Automated Rule-Based Aggregation, Correlation & Blocklist Generator (No AI/ML)")

# Validation Patterns
DOMAIN_REGEX = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")

def detect_type(val):
    val = val.strip()
    try:
        ipaddress.ip_address(val)
        return "ip"
    except ValueError:
        pass
    if DOMAIN_REGEX.match(val):
        return "domain"
    elif MD5_REGEX.match(val) or SHA256_REGEX.match(val):
        return "hash"
    return "unknown"

uploaded_files = st.file_uploader("Upload TI Feed Files (TXT, CSV, JSON)", accept_multiple_files=True)

if uploaded_files:
    master_iocs = defaultdict(set)
    total_feeds = len(uploaded_files)

    for file in uploaded_files:
        content = file.read().decode("utf-8", errors="ignore")
        lines = content.splitlines()
        for line in lines:
            tokens = re.split(r"[,;\s]+", line.strip())
            for token in tokens:
                t_type = detect_type(token)
                if t_type != "unknown":
                    master_iocs[(token, t_type)].add(file.name)

    records = []
    for (ioc, ioc_type), sources in master_iocs.items():
        freq = len(sources)
        severity = "High" if freq >= 2 else "Low"
        records.append({
            "Indicator": ioc,
            "Type": ioc_type,
            "Frequency": freq,
            "Severity": severity,
            "Sources": ", ".join(sources)
        })

    st.subheader("📊 Correlated Threat Indicators")
    st.dataframe(records, use_container_width=True)

    col1, col2, col3 = st.columns(3)
    ip_block = "\n".join([r["Indicator"] for r in records if r["Type"] == "ip"])
    domain_block = "\n".join([r["Indicator"] for r in records if r["Type"] == "domain"])
    hash_block = "\n".join([r["Indicator"] for r in records if r["Type"] == "hash"])

    with col1:
        st.download_button("📥 Download Firewall IP Blocklist", ip_block, file_name="blocklist_ips.txt")
    with col2:
        st.download_button("📥 Download DNS Domain Blocklist", domain_block, file_name="blocklist_domains.txt")
    with col3:
        st.download_button("📥 Download EDR Hash Blocklist", hash_block, file_name="blocklist_hashes.txt")

    st.success(f"Processed {total_feeds} feeds successfully!")
else:
    st.info("Feed files upload pannu machi to see threat correlation.")
