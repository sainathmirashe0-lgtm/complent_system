from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from sqlalchemy import func
import random

# ---------------- APP SETUP ----------------
app = Flask(__name__)
app.secret_key = "secret123"

app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+mysqlconnector://root:@127.0.0.1:3306/complaint_system"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# ---------------- MODELS ----------------
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="user")
    otp = db.Column(db.String(6))
    otp_expiry = db.Column(db.DateTime)

class Complaint(db.Model):
    __tablename__ = "complaint"
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), default="Pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

# ---------------- HELPERS ----------------
def is_admin():
    return session.get("user_role") == "admin"

def generate_otp():
    return str(random.randint(100000, 999999))

# ---------------- REGISTER ----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        confirm = request.form["confirm"]

        if password != confirm:
            flash("Passwords do not match", "danger")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("User already exists", "danger")
            return redirect(url_for("register"))

        user = User(email=email, password=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()

        flash("Registration successful", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

# ---------------- LOGIN ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(email=request.form["email"]).first()

        if user and check_password_hash(user.password, request.form["password"]):
            session.clear()
            session["user_id"] = user.id
            session["user_role"] = user.role
            return redirect(url_for("dashboard"))

        flash("Invalid login", "danger")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------------- FORGOT PASSWORD ----------------
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        user = User.query.filter_by(email=request.form["email"]).first()
        if not user:
            flash("Email not found", "danger")
            return redirect(url_for("forgot_password"))

        otp = generate_otp()
        user.otp = otp
        user.otp_expiry = datetime.now() + timedelta(minutes=5)
        db.session.commit()

        session["otp_email"] = user.email
        print("OTP:", otp)  # demo

        return redirect(url_for("verify_otp"))

    return render_template("forgot_password.html")

# ---------------- VERIFY OTP ----------------
@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    email = session.get("otp_email")
    if not email:
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        otp = request.form["otp"]
        user = User.query.filter_by(email=email, otp=otp).first()

        if not user:
            flash("Invalid OTP", "danger")
            return redirect(url_for("verify_otp"))

        if datetime.now() > user.otp_expiry:
            flash("OTP expired", "danger")
            return redirect(url_for("forgot_password"))

        session["reset_user_id"] = user.id
        return redirect(url_for("reset_password"))

    return render_template("verify_otp.html", email=email)

# ---------------- RESEND OTP ----------------
@app.route("/resend-otp", methods=["POST"])
def resend_otp():
    email = session.get("otp_email")
    if not email:
        return redirect(url_for("forgot_password"))

    user = User.query.filter_by(email=email).first()
    otp = generate_otp()
    user.otp = otp
    user.otp_expiry = datetime.now() + timedelta(minutes=5)
    db.session.commit()

    print("Resent OTP:", otp)
    flash("New OTP sent", "success")
    return redirect(url_for("verify_otp"))

# ---------------- RESET PASSWORD ----------------
@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if "reset_user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        user = db.session.get(User, session["reset_user_id"])
        user.password = generate_password_hash(request.form["password"])
        user.otp = None
        user.otp_expiry = None
        db.session.commit()

        session.clear()
        flash("Password reset successful", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html")

# ---------------- COMPLAINT ----------------
@app.route("/", methods=["GET", "POST"])
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        db.session.add(Complaint(
            category=request.form["category"],
            description=request.form["description"],
            user_id=session["user_id"]
        ))
        db.session.commit()
        return redirect(url_for("dashboard"))

    return render_template("index.html")

# ---------------- DASHBOARD ----------------
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    complaints = Complaint.query.all() if is_admin() else \
        Complaint.query.filter_by(user_id=session["user_id"]).all()

    return render_template("dashboard.html", complaints=complaints, is_admin=is_admin())

# ---------------- CHART DATA API ----------------
@app.route("/api/dashboard-data")
def dashboard_data():
    query = Complaint.query
    if not is_admin():
        query = query.filter_by(user_id=session["user_id"])

    status = dict(query.with_entities(
        Complaint.status, func.count(Complaint.id)
    ).group_by(Complaint.status).all())

    monthly = [0]*12
    for m, c in query.with_entities(
        func.month(Complaint.created_at), func.count()
    ).group_by(func.month(Complaint.created_at)):
        monthly[m-1] = c

    return jsonify({
        "status": {
            "Approved": status.get("Approved", 0),
            "Pending": status.get("Pending", 0),
            "Rejected": status.get("Rejected", 0),
        },
        "monthly": monthly
    })

# ---------------- ADMIN STATUS ----------------
@app.route("/status", methods=["POST"])
def update_status():
    if not is_admin():
        return redirect(url_for("dashboard"))

    c = db.session.get(Complaint, request.form["id"])
    c.status = request.form["status"]
    db.session.commit()
    return redirect(url_for("dashboard"))

# ---------------- RUN ----------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)

