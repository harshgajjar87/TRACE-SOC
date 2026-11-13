"""Day 25 dashboard view — Detection Rule Quality."""

from __future__ import annotations

import streamlit as st

try:
    import plotly.express as px
    _PLOTLY = True
except ImportError:
    _PLOTLY = False

from detection.quality import (
    get_rule_quality_summary,
    get_overall_quality_metrics,
    get_category_quality_breakdown,
)


_BAND_COLORS = {
    "GOOD": "#34d399",
    "ACCEPTABLE": "#fbbf24",
    "NEEDS_REVIEW": "#fb923c",
    "POOR": "#fb7185",
}


def _style_chart(fig, height=320):
    fig.update_layout(
        template="plotly_dark", height=height,
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#b9c9dc"),
        margin=dict(l=12, r=12, t=48, b=12),
        legend=dict(font=dict(color="#a9bdd3")),
        xaxis=dict(gridcolor="rgba(119,148,181,.13)"),
        yaxis=dict(gridcolor="rgba(119,148,181,.13)"),
    )
    return fig


def render_detection_quality():
    st.markdown("""
    <div class='top-banner'>
      <div class='eyebrow'>DETECTION  /  RULE QUALITY</div>
      <div class='banner-title'>Detection Rule Quality</div>
      <div class='banner-sub'>Score every detection rule against analyst feedback, alert volume and false positive rates.</div>
    </div>""", unsafe_allow_html=True)

    left, right = st.columns([3, 1])
    with right:
        if st.button("↻ Refresh", use_container_width=True):
            st.rerun()

    metrics = get_overall_quality_metrics()
    band = metrics.get("band_counts", {})

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.markdown(
        f"<div class='metric-card'><div class='metric-label'>TOTAL RULES</div>"
        f"<div class='metric-value' style='color:#67d5f5;'>{metrics['total_rules']}</div></div>",
        unsafe_allow_html=True,
    )
    m2.markdown(
        f"<div class='metric-card'><div class='metric-label'>GOOD</div>"
        f"<div class='metric-value' style='color:#34d399;'>{band.get('GOOD', 0)}</div></div>",
        unsafe_allow_html=True,
    )
    m3.markdown(
        f"<div class='metric-card'><div class='metric-label'>NEEDS REVIEW</div>"
        f"<div class='metric-value' style='color:#fb923c;'>{band.get('NEEDS_REVIEW', 0)}</div></div>",
        unsafe_allow_html=True,
    )
    m4.markdown(
        f"<div class='metric-card'><div class='metric-label'>POOR</div>"
        f"<div class='metric-value' style='color:#fb7185;'>{band.get('POOR', 0)}</div></div>",
        unsafe_allow_html=True,
    )
    m5.markdown(
        f"<div class='metric-card'><div class='metric-label'>NEVER FIRED</div>"
        f"<div class='metric-value' style='color:#fbbf24;'>{metrics.get('never_fired', 0)}</div></div>",
        unsafe_allow_html=True,
    )
    st.caption(
        f"Overall false positive rate: {round(metrics.get('overall_fp_rate', 0) * 100, 1)}%  |  "
        f"Total alerts analysed: {metrics.get('total_alerts', 0)}"
    )

    st.write("")
    left_col, right_col = st.columns([1.2, 1])

    with left_col:
        st.markdown("<div class='section-kicker'>QUALITY BAND DISTRIBUTION</div>", unsafe_allow_html=True)
        if _PLOTLY and any(band.values()):
            fig = px.bar(
                x=list(band.keys()),
                y=list(band.values()),
                color=list(band.keys()),
                color_discrete_map=_BAND_COLORS,
                labels={"x": "Band", "y": "Rules"},
            )
            fig.update_traces(marker_line_width=0)
            st.plotly_chart(_style_chart(fig), use_container_width=True, config={"displayModeBar": False})
        else:
            st.info("No alert data yet — run the detection engine first.")

    with right_col:
        st.markdown("<div class='section-kicker'>CATEGORY BREAKDOWN</div>", unsafe_allow_html=True)
        cat_data = get_category_quality_breakdown()
        if cat_data:
            st.dataframe(
                [{
                    "category": c["category"],
                    "rules": c["rule_count"],
                    "alerts": c["total_alerts"],
                    "fp_rate": f"{round(c['fp_rate'] * 100, 1)}%",
                    "poor": c["poor_count"],
                    "needs_review": c["needs_review_count"],
                } for c in cat_data],
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No category data available.")

    st.write("")
    st.markdown("<div class='section-kicker'>RULE-LEVEL QUALITY SCORES</div>", unsafe_allow_html=True)

    band_filter = st.selectbox(
        "Filter by quality band",
        ["ALL", "POOR", "NEEDS_REVIEW", "ACCEPTABLE", "GOOD"],
        key="dq_band",
    )

    rules = get_rule_quality_summary()
    if band_filter != "ALL":
        rules = [r for r in rules if r["quality_band"] == band_filter]

    if rules:
        display = []
        for r in rules:
            display.append({
                "rule_id": r["rule_id"],
                "name": r["name"],
                "category": r["category"],
                "severity": r["severity"],
                "alerts": r["total_alerts"],
                "fp_count": r["false_positive_count"],
                "fp_rate": f"{round(r['fp_rate'] * 100, 1)}%",
                "open": r["open_count"],
                "score": r["quality_score"],
                "band": r["quality_band"],
            })
        st.dataframe(display, use_container_width=True, hide_index=True)

        # Expandable suggestions
        rules_with_suggestions = [r for r in rules if r["suggestions"]]
        if rules_with_suggestions:
            st.write("")
            st.markdown("<div class='section-kicker'>TUNING SUGGESTIONS</div>", unsafe_allow_html=True)
            for r in rules_with_suggestions[:15]:
                with st.expander(f"{r['rule_id']} — {r['name']} [{r['quality_band']}]"):
                    for suggestion in r["suggestions"]:
                        st.markdown(f"• {suggestion}")
    else:
        st.info("No rules match the selected filter.")

    st.info(
        "Quality scores are heuristic indicators based on analyst feedback in the alerts table. "
        "A POOR score requires analyst review; it does not prove the rule is broken."
    )
