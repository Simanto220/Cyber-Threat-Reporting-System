from flask import Flask, render_template_string, request, redirect, url_for, session, flash
import sqlite3
from datetime import datetime

app = Flask(__name__)
app.secret_key = "cyber_security_secret_key"

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "12345"

# ================= Database =================
def create_database():
    conn = sqlite3.connect("cyber_reports.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reporter_name TEXT NOT NULL,
            email TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            threat_level TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT NOT NULL,
            report_time TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# ================= Home Page =================
home_page = """
<!DOCTYPE html>
<html>
<head>
    <title>Cyber Threat Reporting System</title>
    <style>
        body { margin:0; font-family:Arial; background:#0f172a; color:white; }
        .container { width:85%; margin:auto; padding:30px; }
        .box { background:#1e293b; padding:25px; border-radius:12px; margin-bottom:25px; box-shadow:0 5px 20px #000; }
        h1, h2 { color:#38bdf8; }
        input, select, textarea {
            width:100%; padding:12px; margin:8px 0 15px;
            border-radius:8px; border:none; background:#334155; color:white;
        }
        textarea { height:110px; }
        button, .btn {
            background:#2563eb; color:white; padding:10px 18px;
            border:none; border-radius:8px; cursor:pointer; text-decoration:none;
        }
        button:hover, .btn:hover { background:#1d4ed8; }
        .nav { text-align:right; margin-bottom:15px; }
        .success { background:#166534; padding:12px; border-radius:8px; margin-bottom:15px; }
        .error { background:#991b1b; padding:12px; border-radius:8px; margin-bottom:15px; }
        .info { color:#cbd5e1; line-height:1.6; }
    </style>
</head>
<body>
<div class="container">

    <div class="nav">
        <a class="btn" href="/login">Admin Login</a>
    </div>

    {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
            {% for category, message in messages %}
                <div class="{{ category }}">{{ message }}</div>
            {% endfor %}
        {% endif %}
    {% endwith %}

    <div class="box">
        <h1>Cyber Threat Reporting System</h1>
        <p class="info">
            This web application helps users report cyber threats such as phishing websites,
            malware links, suspicious emails, fake login pages, and unknown cyber attacks.
        </p>
    </div>

    <div class="box">
        <h2>Submit Cyber Threat Report</h2>

        <form method="POST" action="/submit">
            <label>Reporter Name</label>
            <input type="text" name="reporter_name" placeholder="Enter your name" required>

            <label>Email Address</label>
            <input type="email" name="email" placeholder="example@gmail.com" required>

            <label>Threat Type</label>
            <select name="threat_type" required>
                <option value="">Select Threat Type</option>
                <option value="Phishing Website">Phishing Website</option>
                <option value="Malware Link">Malware Link</option>
                <option value="Suspicious Email">Suspicious Email</option>
                <option value="Fake Login Page">Fake Login Page</option>
                <option value="Unknown Threat">Unknown Threat</option>
            </select>

            <label>Threat Level</label>
            <select name="threat_level" required>
                <option value="">Select Threat Level</option>
                <option value="Low">Low</option>
                <option value="Medium">Medium</option>
                <option value="High">High</option>
            </select>

            <label>Description</label>
            <textarea name="description" minlength="10" placeholder="Write at least 10 characters about the threat..." required></textarea>

            <button type="submit">Submit Report</button>
        </form>
    </div>

</div>
</body>
</html>
"""


# ================= Login Page =================
login_page = """
<!DOCTYPE html>
<html>
<head>
    <title>Admin Login</title>
    <style>
        body { background:#0f172a; font-family:Arial; color:white; }
        .box { width:420px; margin:100px auto; background:#1e293b; padding:30px; border-radius:12px; box-shadow:0 5px 20px #000; }
        h2 { color:#38bdf8; }
        input { width:100%; padding:12px; margin:10px 0; border:none; border-radius:8px; background:#334155; color:white; }
        button, .btn { background:#2563eb; color:white; padding:10px 18px; border:none; border-radius:8px; text-decoration:none; }
        .error { color:#f87171; }
        a { color:#38bdf8; }
    </style>
</head>
<body>
<div class="box">
    <h2>Admin Login</h2>

    <form method="POST" action="/login">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Login</button>
    </form>

    <p class="error">{{ message }}</p>
    <p>Demo Login: <b>admin</b> / <b>12345</b></p>
    <a href="/">Back to Home</a>
</div>
</body>
</html>
"""


# ================= Dashboard Page =================
dashboard_page = """
<!DOCTYPE html>
<html>
<head>
    <title>Admin Dashboard</title>
    <style>
        body { margin:0; font-family:Arial; background:#0f172a; color:white; }
        .container { width:95%; margin:auto; padding:25px; }
        .box { background:#1e293b; padding:20px; border-radius:12px; margin-bottom:20px; box-shadow:0 5px 20px #000; }
        h1, h2 { color:#38bdf8; }
        table { width:100%; border-collapse:collapse; margin-top:15px; font-size:14px; }
        th { background:#2563eb; padding:10px; }
        td { border:1px solid #475569; padding:8px; text-align:center; }
        input, select { padding:10px; border-radius:6px; border:none; margin:5px; background:#334155; color:white; }
        button, .btn {
            background:#2563eb; color:white; padding:8px 14px;
            border:none; border-radius:6px; text-decoration:none; cursor:pointer;
        }
        .danger { background:#dc2626; }
        .resolve { background:#16a34a; }
        .low { color:#22c55e; font-weight:bold; }
        .medium { color:#facc15; font-weight:bold; }
        .high { color:#ef4444; font-weight:bold; }
        .pending { color:#facc15; font-weight:bold; }
        .resolved { color:#22c55e; font-weight:bold; }
        .success { background:#166534; padding:12px; border-radius:8px; margin-bottom:15px; }
    </style>
</head>
<body>
<div class="container">

    {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
            {% for category, message in messages %}
                <div class="{{ category }}">{{ message }}</div>
            {% endfor %}
        {% endif %}
    {% endwith %}

    <div class="box">
        <h1>Admin Dashboard</h1>
        <a class="btn" href="/">Home</a>
        <a class="btn danger" href="/logout">Logout</a>
    </div>

    <div class="box">
        <h2>Search and Filter Reports</h2>

        <form method="GET" action="/dashboard">
            <input type="text" name="search" placeholder="Search name/email/type" value="{{ search }}">
            <select name="level">
                <option value="">All Threat Levels</option>
                <option value="Low" {% if level=="Low" %}selected{% endif %}>Low</option>
                <option value="Medium" {% if level=="Medium" %}selected{% endif %}>Medium</option>
                <option value="High" {% if level=="High" %}selected{% endif %}>High</option>
            </select>

            <select name="status">
                <option value="">All Status</option>
                <option value="Pending" {% if status=="Pending" %}selected{% endif %}>Pending</option>
                <option value="Resolved" {% if status=="Resolved" %}selected{% endif %}>Resolved</option>
            </select>

            <button type="submit">Search</button>
            <a class="btn" href="/dashboard">Reset</a>
        </form>
    </div>

    <div class="box">
        <h2>Submitted Cyber Threat Reports</h2>

        <table>
            <tr>
                <th>ID</th>
                <th>Reporter</th>
                <th>Email</th>
                <th>Threat Type</th>
                <th>Level</th>
                <th>Description</th>
                <th>Status</th>
                <th>Time</th>
                <th>Action</th>
            </tr>

            {% for r in reports %}
            <tr>
                <td>{{ r[0] }}</td>
                <td>{{ r[1] }}</td>
                <td>{{ r[2] }}</td>
                <td>{{ r[3] }}</td>

                {% if r[4] == "Low" %}
                    <td class="low">{{ r[4] }}</td>
                {% elif r[4] == "Medium" %}
                    <td class="medium">{{ r[4] }}</td>
                {% else %}
                    <td class="high">{{ r[4] }}</td>
                {% endif %}

                <td>{{ r[5] }}</td>

                {% if r[6] == "Resolved" %}
                    <td class="resolved">{{ r[6] }}</td>
                {% else %}
                    <td class="pending">{{ r[6] }}</td>
                {% endif %}

                <td>{{ r[7] }}</td>
                <td>
                    <a class="btn resolve" href="/resolve/{{ r[0] }}">Resolve</a>
                    <a class="btn danger" href="/delete/{{ r[0] }}" onclick="return confirm('Are you sure you want to delete this report?');">Delete</a>
                </td>
            </tr>
            {% endfor %}
        </table>

        {% if reports|length == 0 %}
            <p>No report found.</p>
        {% endif %}
    </div>

</div>
</body>
</html>
"""


# ================= Routes =================
@app.route("/")
def home():
    return render_template_string(home_page)


@app.route("/submit", methods=["POST"])
def submit_report():
    reporter_name = request.form["reporter_name"].strip()
    email = request.form["email"].strip()
    threat_type = request.form["threat_type"].strip()
    threat_level = request.form["threat_level"].strip()
    description = request.form["description"].strip()

    if len(description) < 10:
        flash("Description must be at least 10 characters.", "error")
        return redirect(url_for("home"))

    status = "Pending"
    report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = sqlite3.connect("cyber_reports.db")
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO reports
        (reporter_name, email, threat_type, threat_level, description, status, report_time)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (reporter_name, email, threat_type, threat_level, description, status, report_time))

    conn.commit()
    conn.close()

    flash("Report submitted successfully!", "success")
    return redirect(url_for("home"))


@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["admin"] = True
            flash("Admin logged in successfully.", "success")
            return redirect(url_for("dashboard"))
        else:
            message = "Invalid username or password"

    return render_template_string(login_page, message=message)


@app.route("/dashboard")
def dashboard():
    if "admin" not in session:
        return redirect(url_for("login"))

    search = request.args.get("search", "").strip()
    level = request.args.get("level", "").strip()
    status = request.args.get("status", "").strip()

    conn = sqlite3.connect("cyber_reports.db")
    cursor = conn.cursor()

    query = "SELECT * FROM reports WHERE 1=1"
    values = []

    if search:
        query += " AND (reporter_name LIKE ? OR email LIKE ? OR threat_type LIKE ? OR description LIKE ?)"
        values.extend([f"%{search}%", f"%{search}%", f"%{search}%", f"%{search}%"])

    if level:
        query += " AND threat_level = ?"
        values.append(level)

    if status:
        query += " AND status = ?"
        values.append(status)

    query += " ORDER BY id DESC"

    cursor.execute(query, values)
    reports = cursor.fetchall()

    conn.close()

    return render_template_string(
        dashboard_page,
        reports=reports,
        search=search,
        level=level,
        status=status
    )


@app.route("/resolve/<int:report_id>")
def resolve_report(report_id):
    if "admin" not in session:
        return redirect(url_for("login"))

    conn = sqlite3.connect("cyber_reports.db")
    cursor = conn.cursor()

    cursor.execute("UPDATE reports SET status = ? WHERE id = ?", ("Resolved", report_id))

    conn.commit()
    conn.close()

    flash("Report marked as resolved.", "success")
    return redirect(url_for("dashboard"))


@app.route("/delete/<int:report_id>")
def delete_report(report_id):
    if "admin" not in session:
        return redirect(url_for("login"))

    conn = sqlite3.connect("cyber_reports.db")
    cursor = conn.cursor()

    cursor.execute("DELETE FROM reports WHERE id = ?", (report_id,))

    conn.commit()
    conn.close()

    flash("Report deleted successfully.", "success")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    flash("Admin logged out successfully.", "success")
    return redirect(url_for("home"))


# ================= Main Program =================
if __name__ == "__main__":
    create_database()
    app.run(debug=True)