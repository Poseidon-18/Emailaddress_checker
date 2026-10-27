from flask import Flask, jsonify, render_template, request
import verifier

app = Flask(__name__)


@app.get("/")
def index():
    return render_template("index.html", max_addresses=verifier.MAX_ADDRESSES)


@app.get("/api/status")
def status():
    ok, why = verifier.smtp_available()
    return jsonify(smtp_probe=bool(ok), detail=why)


@app.post("/api/check")
def check():
    data = request.get_json(silent=True) or {}
    emails = verifier.parse_addresses(data.get("emails", ""))
    if not emails:
        return jsonify(error="Paste at least one email address."), 400
    truncated = len(emails) > verifier.MAX_ADDRESSES
    results = verifier.check_many(emails[: verifier.MAX_ADDRESSES])
    summary = {k: sum(r["status"] == k for r in results)
               for k in (verifier.DELIVERABLE, verifier.UNDELIVERABLE, verifier.UNKNOWN)}
    return jsonify(results=results, summary=summary, truncated=truncated, limit=verifier.MAX_ADDRESSES)


if __name__ == "__main__":
    app.run(debug=True)
