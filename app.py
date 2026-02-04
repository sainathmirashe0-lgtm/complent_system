from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from sqlalchemy import func
import random
import os
import base64
import smtplib
from email.message import EmailMessage
from werkzeug.utils import secure_filename


# ================= EMAIL CONFIG =================

EMAIL_ADDRESS = "sainathmirashe0@gmail.com"
EMAIL_PASSWORD = "YOUR_GMAIL_APP_PASSWORD"  # ⚠️ Use ENV in production

def send_email(to, subject, body):
    try:
        msg = EmailMessage()
        msg["From"] = EMAIL_ADDRESS
        msg["To"] = to
        msg["Subject"] = subject
        msg.set_content(body)

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(msg)

        print("Email sent to", to)

    except Exception as e:
        print("Email error:", e)

# ================= APP SETUP =================

app = Flask(__name__)
app.secret_key = "secret123"

app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+mysqlconnector://root:@127.0.0.1:3306/complaint_system"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "pool_recycle": 280
}

UPLOAD_FOLDER = "static/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

db = SQLAlchemy(app)

# ================= MODELS =================

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="user")
    department = db.Column(db.String(50))
    profile_photo = db.Column(db.String(255))
    otp = db.Column(db.String(6))
    otp_expiry = db.Column(db.DateTime)
    balance = db.Column(db.Integer, default=0)
class Withdrawal(db.Model):
    __tablename__ = "withdrawals"

    id = db.Column(db.Integer, primary_key=True)
    worker_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    amount = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default="Pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Complaint(db.Model):
    __tablename__ = "complaint"

    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(255))
    status = db.Column(db.String(50), default="Pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey("users.id"))
    work_image = db.Column(db.String(255))
    rating = db.Column(db.Integer)
    feedback = db.Column(db.Text)

class Solution(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    solution = db.Column(db.Text, nullable=False)
    likes = db.Column(db.Integer, default=0)
    dislikes = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SolutionReaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    solution_id = db.Column(db.Integer, db.ForeignKey("solution.id"), nullable=False)
    reaction = db.Column(db.String(10), nullable=False)  # like / dislike
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ================= HELPERS =================
def is_admin():
    return session.get("user_role") == "admin"

def is_worker():
    return session.get("user_role") == "worker"

def is_logged_in():
    return session.get("user_id") is not None

def generate_otp():
    return str(random.randint(100000, 999999))

# ================= TEST EMAIL =================

@app.route("/test-email")
def test_email():
    send_email(EMAIL_ADDRESS, "Test Email", "Email system working ✅")
    return "Email sent"

# ================= AUTH =================
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    # default step
    step = "email"

    # ---------------- STEP 1: EMAIL ----------------
    if request.method == "POST" and "email" in request.form:
        email = request.form["email"]
        user = User.query.filter_by(email=email).first()

        if not user:
            flash("Email not registered", "danger")
            return render_template("forgot_password.html", step="email")

        otp = generate_otp()
        user.otp = otp
        user.otp_expiry = datetime.now() + timedelta(minutes=5)
        db.session.commit()

        # store email in session
        session["reset_email"] = email

        # demo (console)
        print("OTP:", otp)

        # optional email
        send_email(
            to=email,
            subject="Password Reset OTP",
            body=f"Your OTP is {otp}. It is valid for 5 minutes."
        )

        flash("OTP sent to your email", "success")
        step = "otp"

    # ---------------- STEP 2: OTP ----------------
    elif request.method == "POST" and "otp" in request.form:
        otp = request.form["otp"]
        email = session.get("reset_email")

        if not email:
            flash("Session expired. Try again.", "danger")
            return redirect(url_for("forgot_password"))

        user = User.query.filter_by(email=email, otp=otp).first()

        if not user:
            flash("Invalid OTP", "danger")
            step = "otp"

        elif datetime.now() > user.otp_expiry:
            flash("OTP expired", "danger")
            step = "email"

        else:
            session["reset_user_id"] = user.id
            flash("OTP verified", "success")
            step = "reset"

    # ---------------- STEP 3: RESET PASSWORD ----------------
    elif request.method == "POST" and "password" in request.form:
        password = request.form["password"]
        confirm = request.form["confirm"]

        if password != confirm:
            flash("Passwords do not match", "danger")
            step = "reset"
        else:
            user = User.query.get(session.get("reset_user_id"))

            user.password = generate_password_hash(password)
            user.otp = None
            user.otp_expiry = None
            db.session.commit()

            session.clear()
            flash("Password reset successful", "success")
            return redirect(url_for("login"))

    return render_template("forgot_password.html", step=step)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if request.form["password"] != request.form["confirm"]:
            flash("Passwords do not match", "danger")
            return redirect(url_for("register"))

        if User.query.filter_by(email=request.form["email"]).first():
            flash("User already exists", "danger")
            return redirect(url_for("register"))

        user = User(
            email=request.form["email"],
            password=generate_password_hash(request.form["password"])
        )
        db.session.add(user)
        db.session.commit()

        flash("Registration successful", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(email=request.form["email"]).first()

        if user and check_password_hash(user.password, request.form["password"]):
            session.clear()
            session["user_id"] = user.id
            session["user_role"] = user.role

            if user.role == "worker":
                return redirect(url_for("worker_dashboard"))
            return redirect(url_for("dashboard"))

        flash("Invalid credentials", "danger")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ================= COMPLAINT =================
@app.route("/complaint", methods=["GET", "POST"])
def complaint():
    if request.method == "POST":
        category = request.form["category"]
        description = request.form["description"]
        latitude = request.form["latitude"]
        longitude = request.form["longitude"]
        photo_data = request.form["photoData"]

        # Decode image
        if photo_data:
            header, encoded = photo_data.split(",", 1)
            image_data = base64.b64decode(encoded)
            with open("static/uploads/complaint.png", "wb") as f:
                f.write(image_data)

        # Save to DB here
        return "Complaint submitted successfully"

    return render_template("complaint.html")
@app.route("/index", methods=["GET", "POST"])
def index():
    if not is_logged_in():
        return redirect(url_for("login"))

    if request.method == "POST":
        image_path = None
        photo_data = request.form.get("photoData")

        if photo_data:
            _, encoded = photo_data.split(",", 1)
            img = base64.b64decode(encoded)
            name = datetime.now().strftime("%Y%m%d%H%M%S") + ".png"
            with open(os.path.join(UPLOAD_FOLDER, name), "wb") as f:
                f.write(img)
            image_path = f"uploads/{name}"

        complaint = Complaint(
            category=request.form["category"],
            description=request.form["description"],
            image=image_path,
            user_id=session["user_id"]
        )

        db.session.add(complaint)
        db.session.commit()

        flash("Complaint submitted", "success")
        return redirect(url_for("dashboard"))

    return render_template("index.html")

# ================= DASHBOARD =================

@app.route("/")
def home():
    return render_template("navbar.html")

@app.route("/dashboard")
def dashboard():
    if not is_logged_in():
        return redirect(url_for("login"))

    user = db.session.get(User, session["user_id"])

    complaints = Complaint.query.all() if is_admin() else Complaint.query.filter_by(user_id=user.id).all()
    withdrawals = Withdrawal.query.filter_by(status="Pending").all() if is_admin() else []

    return render_template(
        "dashboard.html",
        complaints=complaints,
        is_admin=is_admin(),
        user=user,
        withdrawals=withdrawals
    )
@app.route("/assign-worker/<int:id>", methods=["GET","POST"])
def assign_worker(id):
    complaint = Complaint.query.get(id)
    workers = User.query.filter_by(role="worker").all()

    workers_by_dept = {}
    for w in workers:
        workers_by_dept.setdefault(w.department or "Other", []).append(w)

    if request.method == "POST":
        worker_id = int(request.form["worker_id"])
        complaint.assigned_to = worker_id
        complaint.status = "In Progress"
        db.session.commit()

        worker = User.query.get(worker_id)
        send_email(worker.email, "New Work Assigned",
                   f"Complaint {complaint.id} assigned to you")

        return redirect(url_for("dashboard"))

    return render_template("assign_worker.html",
                           complaint=complaint,
                           workers_by_dept=workers_by_dept)

# ================= WORKER =================
@app.route("/worker/dashboard")
def worker_dashboard():
    worker_id = session.get("user_id")

    complaints = Complaint.query.filter_by(
        assigned_to=worker_id
    ).all()

    return render_template(
        "worker_dashboard.html",
        complaints=complaints
    )

@app.route("/worker-complete/<int:id>", methods=["POST"])
def worker_complete(id):
    c = Complaint.query.get(id)
    file = request.files["work_image"]
    filename = f"work_{id}.png"
    file.save(os.path.join(UPLOAD_FOLDER, filename))
    c.work_image = f"uploads/{filename}"
    c.status = "Completed"
    db.session.commit()
    return redirect(url_for("worker_dashboard"))


# ================= FEEDBACK =================
@app.route("/feedback/<int:id>", methods=["POST"])
def submit_feedback(id):
    c = Complaint.query.get(id)
    c.rating = int(request.form["rating"])
    c.feedback = request.form["feedback"]
    db.session.commit()
    return redirect(url_for("dashboard"))


@app.route("/withdraw-history")
def withdraw_history():
    data = Withdrawal.query.filter_by(worker_id=session["user_id"]).all()
    return render_template("withdraw_history.html", data=data)


@app.route("/admin/approve/<int:id>", methods=["POST"])
def admin_approve(id):
    if not is_admin():
        return {"message": "Unauthorized"}, 403

    complaint = Complaint.query.get_or_404(id)

    if complaint.status == "Approved":
        return {"message": "Already approved"}, 200

    if complaint.status not in ["Resolved", "Completed"]:
        return {"message": "Complaint not completed yet"}, 400

    if not complaint.assigned_to:
        return {"message": "No worker assigned"}, 400

    worker = User.query.get_or_404(complaint.assigned_to)

    rating = complaint.rating or 0

    if rating >= 4.5:
        pay = 500
    elif rating >= 3.5:
        pay = 400
    elif rating >= 2.5:
        pay = 300
    else:
        pay = 100

    worker.balance += pay
    complaint.status = "Approved"

    db.session.commit()

    return {
        "message": "Complaint approved successfully",
        "paid": pay
    }, 200

# ================= CHART API =================
@app.route("/api/dashboard-data")
def dashboard_data():
    status = dict(
        db.session.query(Complaint.status, func.count())
        .group_by(Complaint.status).all()
    )
    monthly = [0]*12
    for m,c in db.session.query(func.month(Complaint.created_at), func.count())\
            .group_by(func.month(Complaint.created_at)):
        monthly[m-1] = c

    return jsonify({"status":status, "monthly":monthly})
# ================= RUN =================

@app.route("/admin/solutions")
def admin_solutions():
    if not is_admin():
        return redirect(url_for("login"))

    solutions = Solution.query.order_by(Solution.created_at.desc()).all()
    return render_template("admin_solutions.html", solutions=solutions)

@app.route("/solution", methods=["GET", "POST"])
def solution():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        category = request.form.get("category")
        solution_text = request.form.get("solution")

        sol = Solution(
            name=name,
            email=email,
            category=category,
            solution=solution_text
        )

        db.session.add(sol)
        db.session.commit()
        print("request.method", request.form)
        flash("Solution submitted successfully")
        return redirect(url_for("dashboard"))

    return render_template("solution.html")

@app.route("/all-solutions")
def all_solutions():
 solutions = Solution.query \
        .order_by(Solution.likes.desc(), Solution.created_at.desc()) \
        .all()
 return render_template("all_solutions.html", solutions=solutions)

@app.route("/solution/<int:id>/like", methods=["POST"])
def like_solution(id):
    user_id = session.get("user_id")
    if not user_id:
        flash("Please login to like solutions")
        return redirect(url_for("login"))

    existing = SolutionReaction.query.filter_by(
        user_id=user_id,
        solution_id=id
    ).first()

    if existing:
        flash("You have already reacted to this solution")
        return redirect(url_for("all_solutions"))

    reaction = SolutionReaction(
        user_id=user_id,
        solution_id=id,
        reaction="like"
    )

    sol = Solution.query.get_or_404(id)
    sol.likes += 1

    db.session.add(reaction)
    db.session.commit()

    return redirect(url_for("all_solutions"))



@app.route("/solution/<int:id>/dislike", methods=["POST"])
def dislike_solution(id):
    user_id = session.get("user_id")
    if not user_id:
        flash("Please login to dislike solutions")
        return redirect(url_for("login"))

    existing = SolutionReaction.query.filter_by(
        user_id=user_id,
        solution_id=id
    ).first()

    if existing:
        flash("You have already reacted to this solution")
        return redirect(url_for("all_solutions"))

    reaction = SolutionReaction(
        user_id=user_id,
        solution_id=id,
        reaction="dislike"
    )

    sol = Solution.query.get_or_404(id)
    sol.dislikes += 1

    db.session.add(reaction)
    db.session.commit()

    return redirect(url_for("all_solutions"))


@app.route("/worker/salary")
def worker_salary():

    if "user_id" not in session:
        return redirect(url_for("login"))

    worker = User.query.get_or_404(session["user_id"])

    completed_jobs = Complaint.query.filter_by(
        assigned_to=worker.id,
        status="Approved"
    ).count()

    avg_rating = db.session.query(
        func.avg(Complaint.rating)
    ).filter(
        Complaint.assigned_to == worker.id,
        Complaint.rating != None
    ).scalar()

    avg_rating = round(avg_rating or 0, 1)

    data = {
        "jobs": completed_jobs,
        "avg_rating": avg_rating,
        "salary": worker.balance   # 🔥 ONLY THIS
    }

    return render_template("worker_salary.html", data=data)


@app.route("/worker/upload/<int:id>", methods=["POST"])
def worker_upload(id):

    complaint = Complaint.query.get_or_404(id)

    file = request.files.get("work_image")
    if not file:
        flash("No file selected", "danger")
        return redirect(url_for("worker_dashboard"))

    filename = secure_filename(file.filename)

    upload_folder = os.path.join("static", "work_images")

    # ✅ create folder if it doesn't exist
    os.makedirs(upload_folder, exist_ok=True)

    file_path = os.path.join(upload_folder, filename)

    file.save(file_path)

    # save relative path in DB
    complaint.work_image = f"work_images/{filename}"
    complaint.status = "Completed"

    db.session.commit()

    flash("Work uploaded successfully!", "success")
    return redirect(url_for("worker_dashboard"))

@app.route("/admin/withdraw/approve/<int:id>", methods=["POST"])
def approve_withdraw(id):
    if not is_admin():
        return redirect(url_for("login"))

    w = Withdrawal.query.get_or_404(id)
    worker = User.query.get(w.worker_id)

    if w.status == "Pending" and w.amount <= worker.balance:
        worker.balance -= w.amount
        w.status = "Approved"
        db.session.commit()
        flash("Withdraw approved & balance deducted", "success")

    return redirect(url_for("dashboard"))


@app.route("/admin/withdraw/reject/<int:id>", methods=["POST"])
def reject_withdraw(id):
    if not is_admin():
        return redirect(url_for("login"))

    w = Withdrawal.query.get_or_404(id)
    w.status = "Rejected"
    db.session.commit()

    flash("Withdraw request rejected", "warning")
    return redirect(url_for("dashboard"))

@app.route("/withdraw", methods=["GET", "POST"])
def withdraw():

    if "user_id" not in session:
        return redirect(url_for("login"))

    worker = User.query.get_or_404(session["user_id"])

    if request.method == "POST":
        amount = int(request.form["amount"])

        if amount <= 0:
            flash("Invalid amount", "danger")
            return redirect(url_for("withdraw"))

        if amount > worker.balance:
            flash("Insufficient balance", "danger")
            return redirect(url_for("withdraw"))

        req = Withdrawal(
            worker_id=worker.id,
            amount=amount,
            status="Pending"
        )

        db.session.add(req)
        db.session.commit()

        flash("Withdraw request sent for admin approval", "success")
        return redirect(url_for("withdraw"))
    return render_template(
    "withdraw.html",
    balance= worker.balance,
    data={"salary": worker.balance}
)





if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, use_reloader=False)
