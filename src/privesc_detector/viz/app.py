"""Privilege Escalation Graph — interactive Dash + dash-cytoscape visualizer.

Run:
    python -m privesc_detector.viz.app
    # then open http://127.0.0.1:8050
"""

from __future__ import annotations

import dash
import dash_cytoscape as cyto
from dash import Input, Output, dcc, html

from privesc_detector.graph.builder import load_graph
from privesc_detector.ingest import crowdstrike, unix_auth
from privesc_detector.viz.convert import collapsed_elements, raw_elements

# ---------------------------------------------------------------------------
# Data — loaded once at startup from the ingest stubs
# ---------------------------------------------------------------------------

_events = crowdstrike.fetch_events() + unix_auth.fetch_events()
_graph = load_graph(_events)
_collapsed = collapsed_elements(_graph)
_raw = raw_elements(_graph)

_all_mechanisms = sorted({
    e["data"]["mechanism"] for e in _collapsed if "source" in e["data"]
})

# ---------------------------------------------------------------------------
# Stylesheet
# ---------------------------------------------------------------------------

STYLESHEET = [
    # Nodes
    {
        "selector": "node",
        "style": {
            "label": "data(label)",
            "text-wrap": "wrap",
            "text-valign": "center",
            "text-halign": "center",
            "font-size": "11px",
            "width": 60,
            "height": 60,
            "color": "#fff",
            "font-weight": "bold",
        },
    },
    {"selector": ".privilege-low",      "style": {"background-color": "#4CAF50"}},
    {"selector": ".privilege-medium",   "style": {"background-color": "#FFC107"}},
    {"selector": ".privilege-high",     "style": {"background-color": "#FF9800"}},
    {"selector": ".privilege-critical", "style": {"background-color": "#F44336"}},
    {
        "selector": "node:selected",
        "style": {"border-color": "#FFD700", "border-width": 3},
    },
    # Edges
    {
        "selector": "edge",
        "style": {
            "label": "data(label)",
            "font-size": "10px",
            "curve-style": "bezier",
            "target-arrow-shape": "triangle",
            "target-arrow-color": "#888",
            "line-color": "#888",
            "arrow-scale": 1.2,
            "text-background-color": "#fff",
            "text-background-opacity": 0.7,
            "text-background-padding": "2px",
        },
    },
    {"selector": ".mechanism-ssh",  "style": {"line-color": "#2196F3", "target-arrow-color": "#2196F3"}},
    {"selector": ".mechanism-kinit", "style": {"line-color": "#9C27B0", "target-arrow-color": "#9C27B0", "line-style": "dashed"}},
    {"selector": ".mechanism-su",   "style": {"line-color": "#FF5722", "target-arrow-color": "#FF5722", "line-style": "dotted"}},
    {"selector": ".mechanism-sudo", "style": {"line-color": "#FF5722", "target-arrow-color": "#FF5722", "line-style": "dotted"}},
    {
        "selector": "edge:selected",
        "style": {"line-color": "#FFD700", "target-arrow-color": "#FFD700", "width": 4},
    },
]

# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------

app = dash.Dash(__name__, title="PrivEsc Graph Explorer")

# Remove the Plotly favicon from the browser tab
app.index_string = """<!DOCTYPE html>
<html>
    <head>
        {%metas%}
        <title>{%title%}</title>
        <link rel="icon" href="data:,">
        {%css%}
    </head>
    <body>
        {%app_entry%}
        <footer>
            {%config%}
            {%scripts%}
            {%renderer%}
        </footer>
    </body>
</html>"""

app.layout = html.Div(
    style={"fontFamily": "sans-serif", "height": "100vh", "display": "flex", "flexDirection": "column"},
    children=[
        # Header
        html.Div(
            style={"background": "#1a1a2e", "color": "#fff", "padding": "12px 20px"},
            children=[html.H2("Privilege Escalation Graph Explorer", style={"margin": 0})],
        ),
        # Controls
        html.Div(
            style={
                "display": "flex", "alignItems": "center", "gap": "32px",
                "padding": "10px 20px", "background": "#f5f5f5", "borderBottom": "1px solid #ddd",
            },
            children=[
                html.Div([
                    html.Label("View", style={"fontWeight": "bold", "marginRight": "8px"}),
                    dcc.RadioItems(
                        id="view-toggle",
                        options=[
                            {"label": " Collapsed", "value": "collapsed"},
                            {"label": " Raw Events", "value": "raw"},
                        ],
                        value="collapsed",
                        inline=True,
                        inputStyle={"marginRight": "4px"},
                        labelStyle={"marginRight": "16px"},
                    ),
                ]),
                html.Div([
                    html.Label("Mechanisms", style={"fontWeight": "bold", "marginRight": "8px"}),
                    dcc.Checklist(
                        id="mechanism-filter",
                        options=[{"label": f" {m}", "value": m} for m in _all_mechanisms],
                        value=_all_mechanisms,
                        inline=True,
                        inputStyle={"marginRight": "4px"},
                        labelStyle={"marginRight": "16px"},
                    ),
                ]),
                # Legend
                html.Div(
                    style={"display": "flex", "gap": "12px", "marginLeft": "auto", "alignItems": "center"},
                    children=[
                        html.Span("Privilege tier:", style={"fontWeight": "bold"}),
                        *[
                            html.Span(label, style={
                                "background": color, "color": "#fff",
                                "padding": "2px 8px", "borderRadius": "4px", "fontSize": "12px",
                            })
                            for label, color in [
                                ("Low", "#4CAF50"), ("Medium", "#FFC107"),
                                ("High", "#FF9800"), ("Critical", "#F44336"),
                            ]
                        ],
                    ],
                ),
            ],
        ),
        # Main area
        html.Div(
            style={"display": "flex", "flex": 1, "overflow": "hidden"},
            children=[
                # Graph
                cyto.Cytoscape(
                    id="graph",
                    elements=_collapsed,
                    layout={"name": "cose", "animate": False},
                    stylesheet=STYLESHEET,
                    style={"flex": "3", "height": "100%"},
                    minZoom=0.3,
                    maxZoom=3,
                ),
                # Detail panel
                html.Div(
                    id="detail-panel",
                    style={
                        "flex": "1", "padding": "16px", "overflowY": "auto",
                        "borderLeft": "1px solid #ddd", "background": "#fafafa",
                        "minWidth": "240px", "maxWidth": "320px",
                    },
                    children=[
                        html.P(
                            "Click a node or edge to inspect it.",
                            style={"color": "#888", "fontStyle": "italic"},
                        )
                    ],
                ),
            ],
        ),
    ],
)

# ---------------------------------------------------------------------------
# Callbacks
# ---------------------------------------------------------------------------


@app.callback(
    Output("graph", "elements"),
    Input("view-toggle", "value"),
    Input("mechanism-filter", "value"),
)
def update_elements(view: str, selected_mechanisms: list[str]) -> list[dict]:
    base = _collapsed if view == "collapsed" else _raw
    selected = set(selected_mechanisms or [])
    return [
        el for el in base
        if "source" not in el["data"]           # always keep nodes
        or el["data"].get("mechanism") in selected  # filter edges
    ]


@app.callback(
    Output("detail-panel", "children"),
    Input("graph", "tapNodeData"),
    Input("graph", "tapEdgeData"),
)
def update_detail(node_data: dict | None, edge_data: dict | None) -> list:
    ctx = dash.callback_context
    if not ctx.triggered or not ctx.triggered[0]["value"]:
        return [html.P("Click a node or edge to inspect it.", style={"color": "#888", "fontStyle": "italic"})]

    trigger_id = ctx.triggered[0]["prop_id"]

    if "tapNodeData" in trigger_id and node_data:
        account, _, host = node_data["id"].partition("|")
        return [
            html.H4("Node", style={"marginTop": 0, "borderBottom": "1px solid #ddd", "paddingBottom": "8px"}),
            _row("Account", account.removeprefix("account:")),
            _row("Host", host.removeprefix("host:")),
            _row("Privilege tier", f"{node_data.get('privilege_tier', 0.0):.2f}"),
        ]

    if "tapEdgeData" in trigger_id and edge_data:
        rows = [
            html.H4("Edge", style={"marginTop": 0, "borderBottom": "1px solid #ddd", "paddingBottom": "8px"}),
            _row("Mechanism", edge_data.get("mechanism", "—")),
            _row("Category", edge_data.get("event_category", "—")),
            _row("Timestamp", edge_data.get("timestamp", "—")),
            _row("Privilege", f"{edge_data.get('src_privilege', 0):.2f} → {edge_data.get('dst_privilege', 0):.2f}"),
        ]
        if "event_count" in edge_data:
            rows.append(_row("Event count", str(edge_data["event_count"])))
        if "event_id" in edge_data:
            rows.append(_row("Event ID", edge_data["event_id"][:8] + "…"))
        return rows

    return [html.P("Click a node or edge to inspect it.", style={"color": "#888", "fontStyle": "italic"})]


def _row(label: str, value: str) -> html.Div:
    return html.Div(
        style={"display": "flex", "justifyContent": "space-between", "padding": "4px 0", "borderBottom": "1px solid #eee"},
        children=[
            html.Span(label, style={"color": "#555", "fontSize": "13px"}),
            html.Span(value, style={"fontWeight": "bold", "fontSize": "13px"}),
        ],
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)
