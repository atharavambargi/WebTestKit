from flask import Flask, render_template, request, send_file, jsonify
import requests as req
from bs4 import BeautifulSoup
import io
import os

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, HRFlowable
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT

# ─── App Setup ───────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"))


# ─── TOOL 1: URL-SENTINEL ────────────────────────────────────────────────────
def check_links(url):
    try:
        if not url.startswith("http"):
            url = "https://" + url
        response = req.get(url, timeout=8, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(response.text, "html.parser")
        links = [
            a.get("href")
            for a in soup.find_all("a", href=True)
            if a.get("href", "").startswith("http")
        ]
        results = []
        for link in links[:15]:
            try:
                res = req.head(link, timeout=4, allow_redirects=True,
                               headers={"User-Agent": "Mozilla/5.0"})
                results.append({"url": link, "status": res.status_code})
            except Exception:
                results.append({"url": link, "status": "Offline/Error"})
        return results if results else [{"url": url, "status": "No external links found"}]
    except Exception as e:
        return [{"url": "Error fetching page", "status": str(e)}]


# ─── TOOL 2: SQL-SCANNER ─────────────────────────────────────────────────────
def scan_sql(url):
    payloads = ["'", "''", "OR 1=1", "' OR '1'='1", "; DROP TABLE", "--"]
    error_signatures = [
        "sql syntax", "mysql_fetch", "native client", "unclosed quotation mark",
        "syntax error", "ora-01756", "warning: mysql", "you have an error in your sql",
        "microsoft ole db", "odbc microsoft access", "jdbc"
    ]
    found_issues = []
    for p in payloads:
        try:
            test_url = f"{url}{p}" if "?" in url else f"{url}?id={p}"
            res = req.get(test_url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
            matched = [sig for sig in error_signatures if sig in res.text.lower()]
            if matched:
                found_issues.append({"payload": p, "signatures": matched})
        except Exception:
            continue
    if found_issues:
        return {"verdict": "VULNERABLE", "label": "SQLi Risk Detected", "issues": found_issues}
    return {"verdict": "SAFE", "label": "Basic Check Passed", "issues": []}


# ─── ROUTES ──────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/sentinel", methods=["POST"])
def api_sentinel():
    data = request.get_json(force=True)
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400
    return jsonify(check_links(url))


@app.route("/api/sql", methods=["POST"])
def api_sql():
    data = request.get_json(force=True)
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400
    return jsonify(scan_sql(url))


@app.route("/api/report", methods=["POST"])
def api_report():
    try:
        form_data = request.form.to_dict()

        def val(key):
            v = form_data.get(key, "") or ""
            return v.strip() if v.strip() else "N/A"

        NAVY       = colors.HexColor("#0F1726")
        ACCENT     = colors.HexColor("#00C48C")
        BLUE_LABEL = colors.HexColor("#0052A4")
        ROW_A      = colors.HexColor("#EBF5FF")
        BORDER_CLR = colors.HexColor("#C8D8EC")
        TEXT_DARK  = colors.HexColor("#1E1E1E")
        TEXT_MUTED = colors.HexColor("#607B99")

        style_h1 = ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=17,
            textColor=ACCENT, alignment=TA_CENTER, spaceAfter=2)
        style_sub = ParagraphStyle("sub", fontName="Helvetica-Oblique", fontSize=9,
            textColor=colors.HexColor("#B4C8DC"), alignment=TA_CENTER)
        style_label = ParagraphStyle("lbl", fontName="Helvetica-Bold", fontSize=10,
            textColor=BLUE_LABEL, alignment=TA_LEFT, leftIndent=4)
        style_value = ParagraphStyle("val", fontName="Helvetica", fontSize=10,
            textColor=TEXT_DARK, alignment=TA_LEFT, leftIndent=4, wordWrap="CJK")
        style_footer = ParagraphStyle("ftr", fontName="Helvetica-Oblique", fontSize=8,
            textColor=TEXT_MUTED, alignment=TA_CENTER)

        fields = [
            ("Defect ID", "id"), ("Project", "project"), ("Product", "product"),
            ("Release", "release"), ("Module", "module"), ("Build / Version", "build"),
            ("Current Status", "status"), ("Summary", "summary"),
            ("Description", "description"), ("Steps to Replicate", "steps"),
            ("Actual Result", "actual"), ("Expected Result", "expected"),
            ("Severity", "severity"), ("Priority", "priority"),
            ("Reported By", "reported"), ("Assigned To", "assigned"),
        ]

        table_data = []
        row_colors = []
        for i, (label, key) in enumerate(fields):
            table_data.append([Paragraph(label, style_label), Paragraph(val(key), style_value)])
            row_colors.append(ROW_A if i % 2 == 0 else colors.white)

        tbl = Table(table_data, colWidths=[55*mm, 120*mm])
        ts = [
            ("GRID",          (0,0), (-1,-1), 0.5, BORDER_CLR),
            ("VALIGN",        (0,0), (-1,-1), "TOP"),
            ("TOPPADDING",    (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ]
        for i, bg in enumerate(row_colors):
            ts.append(("BACKGROUND", (0,i), (-1,i), bg))
        tbl.setStyle(TableStyle(ts))

        def draw_header(canvas, doc):
            canvas.saveState()
            canvas.setFillColor(NAVY)
            canvas.rect(0, A4[1]-38*mm, A4[0], 38*mm, fill=1, stroke=0)
            canvas.restoreState()

        output = io.BytesIO()
        doc = SimpleDocTemplate(output, pagesize=A4,
            leftMargin=15*mm, rightMargin=15*mm,
            topMargin=15*mm, bottomMargin=15*mm)

        story = [
            Spacer(1, 8*mm),
            Paragraph("SOFTWARE TESTING DEFECT REPORT", style_h1),
            Paragraph("MSBTE K-Scheme  |  Course Code: 316314", style_sub),
            Spacer(1, 6*mm),
            tbl,
            Spacer(1, 5*mm),
            HRFlowable(width="100%", thickness=0.7, color=colors.HexColor("#6382BE")),
            Spacer(1, 3*mm),
            Paragraph("Generated by WebTestKit  |  Build By: Atharav Ambargi", style_footer),
        ]
        doc.build(story, onFirstPage=draw_header, onLaterPages=draw_header)
        output.seek(0)

        defect_id = form_data.get("id", "R1").strip() or "R1"
        safe_id = "".join(c for c in defect_id if c.isalnum() or c in "-_")

        return send_file(output, as_attachment=True,
            download_name=f"Defect_Report_{safe_id}.pdf",
            mimetype="application/pdf")

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── Local dev entry point ────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
