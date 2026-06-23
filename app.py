from flask import Flask, render_template, request
import os
import re
from collections import Counter

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/", methods=["GET", "POST"])
def home():
    total_failed = 0
    suspicious_ips = {}

    if request.method == "POST":
        file = request.files["logfile"]

        if file:
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
            file.save(filepath)

            with open(filepath, "r") as f:
                logs = f.readlines()

            failed_ips = []

            for line in logs:
                if "Failed login attempt" in line:
                    total_failed += 1

                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)

                    if ip_match:
                        failed_ips.append(ip_match.group(1))

            suspicious_ips = dict(Counter(failed_ips))

    return render_template(
        "index.html",
        total_failed=total_failed,
        suspicious_ips=suspicious_ips
    )

if __name__ == "__main__":
    app.run(debug=True)
