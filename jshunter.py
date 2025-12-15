import streamlit as st
import re
import pandas as pd

st.set_page_config(
    page_title="JS HUNTER",
    page_icon="🦇",
    layout="wide"
)

st.markdown("""
    <style>
    .stApp { background-color: #000000; color: #cccccc; font-family: 'Courier New', monospace; }
    [data-testid="stSidebar"] { background-color: #050505; border-right: 1px solid #333; }

    h1, h2, h3, h4 { color: #FFD700 !important; text-transform: uppercase; letter-spacing: 2px; }

    div[data-testid="stMetric"] {
        background-color: #0a0a0a;
        border: 1px solid #FFD700;
        border-radius: 0px;
    }
    div[data-testid="stMetricValue"] { color: #FFD700 !important; }
    div[data-testid="stMetricLabel"] { color: #666 !important; }

    .stTextArea textarea {
        background-color: #0a0a0a;
        color: #FFD700;
        border: 1px solid #333;
    }
    .stTextInput > div > div > input { color: #FFD700; background-color: #0a0a0a; border: 1px solid #333; }

    div.stButton > button {
        background-color: #000000;
        color: #FFD700;
        border: 1px solid #FFD700;
        border-radius: 0px;
        font-weight: bold;
        transition: all 0.3s;
    }
    div.stButton > button:hover {
        background-color: #FFD700;
        color: #000000;
        border-color: #FFD700;
        box-shadow: 0 0 10px #FFD700;
    }

    div[data-testid="stDataFrame"] { border: 1px solid #333; }
    div[data-testid="stHeader"] { background-color: #000; }

    ::-webkit-scrollbar { width: 8px; background: #000; }
    ::-webkit-scrollbar-thumb { background: #333; }
    </style>
    """, unsafe_allow_html=True)

SIGNATURES = {
    "SINK": [
        r'innerHTML\s*=',
        r'outerHTML\s*=',
        r'document\.write\(',
        r'dangerouslySetInnerHTML',
        r'eval\(',
        r'setTimeout\s*\(\s*["\']',
        r'setInterval\s*\(\s*["\']',
        r'location\.href\s*=',
        r'location\.search',
        r'location\.hash'
    ],
    "SECRET": [
        r'(?i)(api_key|apikey|access_token|auth_token|api_secret|client_secret)\s*[:=]\s*["\'][a-zA-Z0-9_\-]{10,}["\']',
        r'AKIA[0-9A-Z]{16}',
        r'eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+'
    ],
    "ENDPOINT": [
        r'["\']\/api\/[a-zA-Z0-9_\-\/]+["\']',
        r'["\']\/admin\/[a-zA-Z0-9_\-\/]+["\']',
        r'https?:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(\/[a-zA-Z0-9\-\.\/\?=&_]*)?'
    ],
    "PARAM": [
        r'(?i)(\?|&)(id|user_id|admin|debug|test|redirect|url|path|file|token)=',
        r'(?i)["\'](id|user_id|role|permissions)["\']\s*:'
    ]
}

def scan_payload(content):
    findings = []
    lines = content.split('\n')

    for i, line in enumerate(lines):
        line_num = i + 1

        if len(line) > 5000:
            continue

        for category, regex_list in SIGNATURES.items():
            for pattern in regex_list:
                try:
                    matches = re.finditer(pattern, line)
                    for match in matches:
                        found_text = match.group()
                        display_text = (found_text[:60] + '...') if len(found_text) > 60 else found_text

                        findings.append({
                            "TYPE": category,
                            "MATCH": display_text,
                            "LINE": line_num,
                            "CONTEXT": line.strip()[:200]
                        })
                except re.error:
                    continue

    return pd.DataFrame(findings)

with st.sidebar:
    st.markdown("<h1 style='text-align: center; color: #FFD700;'>JS HUNTER</h1>", unsafe_allow_html=True)
    st.markdown("---")

    input_mode = st.radio("INPUT SOURCE", ["TEXT", "FILE"])
    target_code = ""

    if input_mode == "TEXT":
        target_code = st.text_area("PAYLOAD", height=400)
    else:
        uploaded_file = st.file_uploader("UPLOAD", type=["js", "json", "txt"])
        if uploaded_file:
            target_code = uploaded_file.read().decode("utf-8", errors="ignore")

    st.markdown("---")
    st.caption("v1.4.0")

st.title("STATIC ANALYSIS")

if st.button("EXECUTE", type="primary"):
    if not target_code:
        st.warning("NO DATA")
    else:
        df_results = scan_payload(target_code)

        if not df_results.empty:
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("SECRETS", len(df_results[df_results['TYPE'] == 'SECRET']))
            c2.metric("SINKS", len(df_results[df_results['TYPE'] == 'SINK']))
            c3.metric("PARAMS", len(df_results[df_results['TYPE'] == 'PARAM']))
            c4.metric("ENDPOINTS", len(df_results[df_results['TYPE'] == 'ENDPOINT']))

            st.markdown("### FINDINGS")

            types = st.multiselect("FILTER", df_results["TYPE"].unique(), default=df_results["TYPE"].unique())
            filtered = df_results[df_results["TYPE"].isin(types)]

            st.dataframe(
                filtered,
                use_container_width=True,
                column_config={
                    "LINE": st.column_config.NumberColumn("LN", format="%d", width="small"),
                    "TYPE": st.column_config.TextColumn("TYPE", width="small"),
                    "MATCH": st.column_config.TextColumn("MATCH", width="medium"),
                    "CONTEXT": st.column_config.TextColumn("CONTEXT", width="large"),
                },
                hide_index=True
            )
        else:
            st.success("NO VULNERABILITIES DETECTED")
