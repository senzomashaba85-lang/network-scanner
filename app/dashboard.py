import sys
import os

# Add parent directory to path to import src
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

import streamlit as st
import pandas as pd
import json
from io import BytesIO
import re
import time
from src.scanner import scan_network, scan_ports

# Common port services mapping
PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"
}

def validate_cidr(subnet):
    """Validate CIDR notation"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    if not re.match(pattern, subnet):
        return False
    octets = subnet.split('/')[0].split('.')
    if not all(0 <= int(octet) <= 255 for octet in octets):
        return False
    prefix = int(subnet.split('/')[1])
    return 0 <= prefix <= 32

def get_service_name(port):
    """Get service name for port"""
    return PORT_SERVICES.get(port, "Unknown")

def format_ports(ports_str):
    """Format port list with service names"""
    if not ports_str or ports_str == "None":
        return "None"
    try:
        port_list = [int(p.strip()) for p in ports_str.split(',')]
        formatted = [f"{p} ({get_service_name(p)})" for p in port_list]
        return ", ".join(formatted)
    except:
        return ports_str

def export_to_csv(df):
    """Export to CSV"""
    return df.to_csv(index=False).encode("utf-8")

def export_to_json(results):
    """Export to JSON"""
    return json.dumps(results, indent=4).encode("utf-8")

def export_to_excel(df):
    """Export to Excel"""
    buffer = BytesIO()
    with pd.ExcelWriter(buffer, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, sheet_name="Results")
    buffer.seek(0)
    return buffer

def export_to_txt(results):
    """Export to TXT"""
    txt_data = "Network Scan Results\n"
    txt_data += "=" * 50 + "\n\n"
    for row in results:
        txt_data += f"IP: {row['IP']}\n"
        txt_data += f"Open Ports: {row['Open Ports']}\n"
        txt_data += "-" * 30 + "\n"
    return txt_data.encode("utf-8")

# Page configuration
st.set_page_config(page_title="Network Scanner", layout="wide")

st.title("🔍 Network Scanner Dashboard")
st.caption("App written by Senzo Mashaba")

# Sidebar for settings
with st.sidebar:
    st.header("⚙️ Settings")
    show_services = st.checkbox("Show Service Names", value=True)
    st.markdown("---")
    st.markdown("**About**\nScans networks for active hosts and open ports.")

# Main input section
col1, col2 = st.columns([3, 1])
with col1:
    subnet = st.text_input("Enter subnet (CIDR format)", "192.168.0.0/24", 
                          placeholder="e.g., 192.168.1.0/24")
with col2:
    scan_button = st.button("🔎 Run Scan", use_container_width=True)

# Validation and scanning
if scan_button:
    # Validate CIDR
    if not validate_cidr(subnet):
        st.error("❌ Invalid CIDR format. Please use format like: 192.168.0.0/24")
    else:
        # Run scan with progress tracking
        progress_bar = st.progress(0)
        status_text = st.empty()
        results_container = st.container()
        
        try:
            status_text.info(f"🔍 Scanning subnet: {subnet}")
            start_time = time.time()
            
            # Scan network
            status_text.info("📡 Discovering hosts...")
            hosts = scan_network(subnet)
            
            if not hosts:
                st.warning("⚠️ No active hosts found in this subnet.")
            else:
                results = []
                total_hosts = len(hosts)
                
                for idx, h in enumerate(hosts):
                    # Update progress
                    progress = (idx + 1) / total_hosts
                    progress_bar.progress(progress)
                    status_text.info(f"🔍 Scanning ports on {h} ({idx + 1}/{total_hosts})")
                    
                    ports = scan_ports(h)
                    ports_str = ", ".join(map(str, ports)) if ports else None
                    results.append({
                        "IP": h,
                        "Open Ports": ports_str if ports_str else "None",
                        "Port Count": len(ports) if ports else 0
                    })
                
                # Calculate scan time
                scan_time = time.time() - start_time
                
                # Clear progress indicators
                progress_bar.empty()
                status_text.empty()
                
                # Display results
                st.success(f"✅ Scan complete in {scan_time:.2f}s")
                
                # Results metrics
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Hosts Found", len(results))
                with col2:
                    total_ports = sum(r["Port Count"] for r in results)
                    st.metric("Total Open Ports", total_ports)
                with col3:
                    st.metric("Scan Duration", f"{scan_time:.2f}s")
                
                # Results table
                st.subheader("📊 Scan Results")
                
                # Format ports with service names if enabled
                if show_services:
                    results_display = results.copy()
                    for r in results_display:
                        r["Open Ports"] = format_ports(r["Open Ports"])
                    df = pd.DataFrame(results_display)
                else:
                    df = pd.DataFrame(results)
                
                st.dataframe(df, use_container_width=True, hide_index=True)
                
                # Export section
                st.subheader("📥 Export Results")
                
                export_col1, export_col2, export_col3, export_col4 = st.columns(4)
                
                with export_col1:
                    csv_data = export_to_csv(df)
                    st.download_button(
                        label="📄 CSV",
                        data=csv_data,
                        file_name="scan_results.csv",
                        mime="text/csv",
                        use_container_width=True
                    )
                
                with export_col2:
                    json_data = export_to_json(results)
                    st.download_button(
                        label="📋 JSON",
                        data=json_data,
                        file_name="scan_results.json",
                        mime="application/json",
                        use_container_width=True
                    )
                
                with export_col3:
                    excel_data = export_to_excel(df)
                    st.download_button(
                        label="📊 Excel",
                        data=excel_data,
                        file_name="scan_results.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        use_container_width=True
                    )
                
                with export_col4:
                    txt_data = export_to_txt(results)
                    st.download_button(
                        label="📝 TXT",
                        data=txt_data,
                        file_name="scan_results.txt",
                        mime="text/plain",
                        use_container_width=True
                    )
        
        except Exception as e:
            st.error(f"❌ Scanning error: {str(e)}")
            st.info("Please check your network connection and ensure the subnet is valid.")