"""
CYFROG – centralised stylesheet.
Import and call inject_styles() once at the top of app.py.
"""
import streamlit as st


GLOBAL_CSS = """
<style>
/* ── Variables ─────────────────────────────────────────────────────────── */
:root {
  --bg:      #080f1c;
  --panel:   #101b2b;
  --panel2:  #142238;
  --border:  #24364f;
  --muted:   #91a4bd;
  --text:    #e8f0fa;
  --blue:    #38bdf8;
  --cyan:    #22d3ee;
  --green:   #34d399;
  --amber:   #fbbf24;
  --orange:  #fb923c;
  --red:     #fb7185;
}

/* ── App background ─────────────────────────────────────────────────────── */
html,
body,
[data-testid="stAppViewContainer"],
[data-testid="stAppViewContainer"] > .main {
  background: var(--bg) !important;
}

/* ── Top Header & Sidebar Toggle ────────────────────────────────────────── */
/* Keep stHeader container visible and transparent so the sidebar expand button
   (stExpandSidebarButton / collapsedControl) is always accessible when collapsed */
[data-testid="stHeader"] {
  background: transparent !important;
  color: #e8f0fa !important;
  z-index: 99999 !important;
}

/* Hide Streamlit top decoration line */
[data-testid="stDecoration"] {
  display: none !important;
}

/* Hide default menu, running indicator and deploy buttons, but keep collapse/expand control */
[data-testid="stToolbarActions"],
[data-testid="stStatusWidget"],
#MainMenu {
  visibility: hidden !important;
}

/* Ensure the sidebar toggle / expand button is always prominent and clickable */
[data-testid="stExpandSidebarButton"],
[data-testid="collapsedControl"] {
  display: flex !important;
  visibility: visible !important;
  opacity: 1 !important;
  background: #101b2b !important;
  border: 1px solid #24364f !important;
  border-radius: 8px !important;
  color: #38bdf8 !important;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4) !important;
  margin-top: 6px !important;
  margin-left: 6px !important;
  z-index: 100000 !important;
}

[data-testid="stExpandSidebarButton"]:hover,
[data-testid="collapsedControl"]:hover {
  background: #174260 !important;
  border-color: #38bdf8 !important;
  color: #ffffff !important;
}

/* ── Main content area ──────────────────────────────────────────────────── */
.block-container {
  max-width: 1600px;
  padding-top: 2rem;
  padding-bottom: 3rem;
}

/* ── Sidebar ────────────────────────────────────────────────────────────── */
[data-testid="stSidebar"] {
  background: #0b1524 !important;
  border-right: 1px solid var(--border) !important;
  font-size: 1rem !important;
}

[data-testid="stSidebar"] > div:first-child,
[data-testid="stSidebarContent"] {
  background: #0b1524 !important;
  padding-top: 0.8rem !important;
  overflow-y: auto !important;
}

[data-testid="stSidebarCollapseButton"] button {
  color: #91a4bd !important;
  border-radius: 6px !important;
}
[data-testid="stSidebarCollapseButton"] button:hover {
  color: #38bdf8 !important;
  background: rgba(56, 189, 248, 0.1) !important;
}

/* ── Sidebar radio labels ───────────────────────────────────────────────── */
/* Hide the outer widget label (e.g. module_Command Center) when collapsed */
[data-testid="stSidebar"] [data-testid="stRadio"] div[data-testid="stWidgetLabel"] {
  display: none !important;
}

/* Style only the radio option labels inside the radiogroup */
[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label {
  color: #b8c7da !important;
  font-size: .93rem !important;
  padding: 6px 10px !important;
  border-radius: 8px !important;
  margin-bottom: 2px !important;
  display: flex !important;
  align-items: center !important;
  transition: background .12s, color .12s !important;
  white-space: normal !important;
  word-break: break-word !important;
  cursor: pointer !important;
}

[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label:hover {
  color: #e8f4ff !important;
  background: rgba(56, 189, 248, 0.08) !important;
}

/* Active radio item styling */
[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label[data-checked="true"] {
  color: #38bdf8 !important;
  background: rgba(56, 189, 248, 0.12) !important;
  font-weight: 600 !important;
}

/* ── Typography ─────────────────────────────────────────────────────────── */
[data-testid="stMarkdownContainer"] p,
[data-testid="stMarkdownContainer"] li { color: #c8d5e5; }
h1, h2, h3, h4 { color: var(--text) !important; letter-spacing: -.025em; }
[data-testid="stCaptionContainer"] { color: var(--muted); }
hr { border-color: var(--border); }

/* ── Metric card ────────────────────────────────────────────────────────── */
.metric-card {
  background: linear-gradient(145deg, #14243a, #0e1929);
  border: 1px solid #263b57;
  border-radius: 13px;
  padding: 16px 18px;
  min-height: 112px;
  box-shadow: 0 8px 24px rgba(0,0,0,.16);
}
.metric-label {
  color: #9db0c8;
  font-size: .78rem;
  text-transform: uppercase;
  letter-spacing: .08em;
  font-weight: 650;
}
.metric-value {
  color: #f1f7ff;
  font-size: 2rem;
  font-weight: 750;
  line-height: 1.25;
  margin-top: 8px;
}
.metric-foot { color: #7188a5; font-size: .72rem; margin-top: 3px; }

/* ── Top banner ─────────────────────────────────────────────────────────── */
.top-banner {
  background: linear-gradient(105deg, #10243b, #102b3d 58%, #12233b);
  border: 1px solid #294561;
  border-radius: 16px;
  padding: 20px 24px;
  margin-bottom: 20px;
}
.eyebrow {
  color: #67d6f4;
  font-size: .72rem;
  font-weight: 750;
  letter-spacing: .16em;
  text-transform: uppercase;
}
.banner-title  { color: #f1f7ff; font-size: 1.75rem; font-weight: 760; margin-top: 4px; }
.banner-sub    { color: #a9bdd3; font-size: .88rem; margin-top: 5px; }

/* ── Section kicker ─────────────────────────────────────────────────────── */
.section-kicker {
  color: #7dd3fc;
  text-transform: uppercase;
  letter-spacing: .13em;
  font-size: .72rem;
  font-weight: 750;
  margin: 8px 0 10px;
}

/* ── Status pill ────────────────────────────────────────────────────────── */
.status-pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  border-radius: 999px;
  padding: 5px 12px;
  font-size: .82rem;
  font-weight: 700;
  background: #0f2236;
  color: #67d5f5;
  border: 1px solid #1e4a68;
  letter-spacing: .04em;
}

/* ── Tables / expanders ─────────────────────────────────────────────────── */
div[data-testid="stDataFrame"],
div[data-testid="stTable"] {
  border: 1px solid var(--border);
  border-radius: 10px;
  overflow: hidden;
}
[data-testid="stExpander"] {
  background: #0e1a2a;
  border: 1px solid var(--border);
  border-radius: 10px;
}

/* ── Buttons ────────────────────────────────────────────────────────────── */
.stButton > button,
.stDownloadButton > button {
  border-radius: 9px;
  border: 1px solid #2c5877;
  background: #12314b;
  color: #e8f7ff;
  font-weight: 650;
}
.stButton > button:hover,
.stDownloadButton > button:hover {
  border-color: #38bdf8;
  color: #fff;
  background: #174260;
}
.stButton > button[kind="primary"] {
  background: linear-gradient(90deg, #087eaa, #1263a0);
  border: 0;
}

/* ── Workspace buttons in sidebar ────────────────────────────────────────── */
[data-testid="stSidebar"] div.stButton > button {
  width: 100% !important;
  text-align: left !important;
  justify-content: flex-start !important;
  border-radius: 9px !important;
  border: 1px solid #1e3550 !important;
  background: #0c1829 !important;
  color: #b8cfe8 !important;
  font-size: .95rem !important;
  font-weight: 650 !important;
  padding: 9px 12px !important;
  line-height: 1.4 !important;
  margin-bottom: 2px !important;
  transition: border-color .15s, background .15s, color .15s !important;
}

[data-testid="stSidebar"] div.stButton > button:hover {
  border-color: #38bdf8 !important;
  color: #e8f7ff !important;
  background: #102236 !important;
}

/* Active workspace button (type="primary") */
[data-testid="stSidebar"] div.stButton > button[kind="primary"] {
  border-color: #38bdf8 !important;
  background: linear-gradient(90deg, #0e2a47, #133a60) !important;
  color: #e8f7ff !important;
  box-shadow: 0 0 0 1px rgba(56, 189, 248, 0.2), inset 3px 0 0 #38bdf8 !important;
}

.ws-btn { margin-bottom: 4px; }
.ws-btn button {
  width: 100%;
  text-align: left;
  border-radius: 10px;
  border: 1px solid #1e3550;
  background: #0c1829;
  color: #b8cfe8;
  font-size: .97rem !important;
  font-weight: 600;
  padding: 10px 12px;
  line-height: 1.4;
  transition: border-color .15s, background .15s, color .15s;
  white-space: normal;
  word-break: break-word;
  overflow-wrap: break-word;
  min-height: 0;
}
.ws-btn button:hover {
  border-color: #38bdf8 !important;
  color: #e8f7ff !important;
  background: #102236 !important;
}
.ws-btn-active button {
  border-color: #38bdf8 !important;
  background: #0f2d47 !important;
  color: #e8f7ff !important;
  box-shadow: 0 0 0 1px rgba(56,189,248,.18), inset 2px 0 0 #38bdf8;
}
.ws-btn button p,
.ws-btn button div {
  font-size: .97rem !important;
  margin: 0 !important;
  white-space: normal !important;
  overflow: visible !important;
}

/* ── Sidebar divider / section label / caption ──────────────────────────── */
.ws-divider { height: 1px; background: #1e3550; margin: 10px 0; }
.ws-section-label {
  font-size: .72rem;
  color: #6f88a5;
  letter-spacing: .18em;
  font-weight: 750;
  text-transform: uppercase;
  margin: 4px 0 8px 4px;
}
[data-testid="stSidebar"] [data-testid="stCaptionContainer"] p {
  font-size: .8rem !important;
  color: #62799a !important;
  margin-top: 4px !important;
}

/* ── Form inputs ────────────────────────────────────────────────────────── */
input, textarea, [data-baseweb="select"] > div {
  background-color: #101e30 !important;
}
label, [data-testid="stWidgetLabel"] p { color: #c4d3e5 !important; }

/* ── Misc ───────────────────────────────────────────────────────────────── */
[data-testid="stAlert"] { border-radius: 10px; }
footer   { visibility: hidden; }

/* ── Responsive ─────────────────────────────────────────────────────────── */
@media (max-width: 900px) {
  .block-container { padding-left: 1rem; padding-right: 1rem; }
  .metric-card     { min-height: 96px; }
}
</style>
"""


def inject_styles() -> None:
    """Inject the global TRACE-SOC stylesheet into the Streamlit app."""
    st.markdown(GLOBAL_CSS, unsafe_allow_html=True)
