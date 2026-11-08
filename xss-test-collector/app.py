from flask import Flask, request, jsonify
from datetime import datetime, timezone
import os

app = Flask(__name__)
MAX_BYTES = 2048

@app.get("/health")
def health():
    return jsonify(status="ok", mode="synthetic-test-only")

@app.post("/event")
def receive_event():
    # Only accept the pre-defined synthetic event schema.
    if request.content_length and request.content_length > MAX_BYTES:
        return jsonify(error="too_large"), 413
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error="invalid_json"), 400
    if set(payload.keys()) != {"test_id", "marker"}:
        return jsonify(error="unexpected_fields"), 400
    test_id, marker = payload["test_id"], payload["marker"]
    if not isinstance(test_id, str) or not isinstance(marker, str):
        return jsonify(error="invalid_fields"), 400
    if not (1 <= len(test_id) <= 64 and marker == "XSS_TEST_OK"):
        return jsonify(error="invalid_test"), 400
    # Do not log request headers, IPs, query strings, cookies or bodies.
    timestamp = datetime.now(timezone.utc).isoformat()
    print(f"{timestamp} validated synthetic event: {test_id}", flush=True)
    return jsonify(received=True, test_id=test_id)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))
