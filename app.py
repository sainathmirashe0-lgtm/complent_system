from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from sqlalchemy import func
from flask import send_file
from datetime import date
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from datetime import datetime, timedelta
from functools import wraps
import random,string
import re
import os
import base64
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from werkzeug.utils import secure_filename


# ================= EMAIL CONFIG =================

def send_email(to, subject, body):
    try:
        message = Mail(
            from_email=os.environ.get("FROM_EMAIL"),
            to_emails=to,
            subject=subject,
            plain_text_content=body,      # ✅ IMPORTANT
            html_content=f"<p>{body}</p>" # ✅ SAFE HTML
        )

        sg = SendGridAPIClient(os.environ.get("SENDGRID_API_KEY"))
        sg.send(message)

        print("Email sent successfully to", to)

    except Exception as e:
        print("SendGrid error:", e)

# ================= APP SETUP =================

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")
DISCOUNT_SLABS = [
    {"points": 100, "discount": 5},
    {"points": 200, "discount": 10},
    {"points": 300, "discount": 15},
    {"points": 400, "discount": 20},
    {"points": 500, "discount": 25},
    {"points": 1000, "discount": 50},
]

db_url = os.environ.get("DATABASE_URL")

if not db_url:
    raise Exception("DATABASE_URL is missing!")

if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
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

    # ✅ WORKER PRESENCE
    is_online = db.Column(db.Boolean, default=False)
    last_seen = db.Column(db.DateTime)

    # ✅ WORKER AVAILABILITY
    status = db.Column(
        db.String(30),
        default="available"   # available | busy | emergency_leave | offline
    )
    leave_from = db.Column(db.Date)
    leave_to = db.Column(db.Date)
    leave_reason = db.Column(db.Text)

    department = db.Column(db.String(50))
    profile_photo = db.Column(db.String(255))

    otp = db.Column(db.String(6))
    otp_expiry = db.Column(db.DateTime)

    balance = db.Column(db.Integer, default=0)
    fake_complaints = db.Column(db.Integer, default=0)
    is_blocked = db.Column(db.Boolean, default=False)
    reward_points = db.Column(db.Integer, default=0)

    
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

    latitude = db.Column(db.String(50))
    longitude = db.Column(db.String(50))
    address = db.Column(db.Text)

    status = db.Column(db.String(50), default="Pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey("users.id"))

    work_image = db.Column(db.String(255))
    rating = db.Column(db.Integer)
    rated = db.Column(db.Boolean, default=False)
    feedback = db.Column(db.Text)

    amount = db.Column(db.Integer, default=0)
    salary_paid = db.Column(db.Boolean, default=False)
    approved_at = db.Column(db.DateTime)
    deadline = db.Column(db.DateTime)
    reject_reason = db.Column(db.Text)
    mobile_number = db.Column(db.String(15))  

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
    reaction = db.Column(db.String(10), nullable=False)  
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class BankDetail(db.Model):
    __tablename__ = "bank_details"

    id = db.Column(db.Integer, primary_key=True)
    worker_id = db.Column(db.Integer, db.ForeignKey("users.id"), unique=True)
    bank_name = db.Column(db.String(100))
    account_number = db.Column(db.String(30))
    ifsc_code = db.Column(db.String(20))

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)   # user or worker id
    title = db.Column(db.String(200))
    message = db.Column(db.Text)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Coupon(db.Model):
    __tablename__ = "coupon"
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False)
    discount_percent = db.Column(db.Integer, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    ) 
    expires_at = db.Column(db.DateTime, nullable=False)  # ✅ ADD THIS

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
def block_guard():
    if "user_id" in session:
        user = User.query.get(session["user_id"])
        if user and user.is_blocked:
            flash("🚫 Your account is blocked. You cannot perform this action.", "danger")
            return True
    return False

def login_and_block_guard():
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not is_logged_in():
                return redirect(url_for("login"))

            user = User.query.get(session["user_id"])
            if user and user.is_blocked:
                flash("🚫 Your account is blocked.", "danger")
                return redirect(url_for("notifications"))

            return f(*args, **kwargs)
        return wrapper
    return decorator
def auto_reset_leave():
    db.session.execute(
        db.text("""
            UPDATE users
            SET status='available',
                leave_from=NULL,
                leave_to=NULL,
                leave_reason=NULL
            WHERE role='worker'
              AND status='emergency_leave'
              AND leave_to < :today
        """),
        {"today": date.today()}
    )
    db.session.commit()

def create_notification(user_id, title, message, email=None):
    n = Notification(
        user_id=user_id,
        title=title,
        message=message
    )
    db.session.add(n)
    db.session.commit()

    if email:
        send_email(
            to=email,
            subject=title,
            body=message
        )
def generate_coupon_code():
    return "OM-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=6))


@app.route("/init-db")
def init_db():
    db.create_all()
    return "Database tables created!"

@app.route("/coupon", methods=["GET", "POST"])

@login_and_block_guard()
def coupon():
    user = User.query.get(session["user_id"])

    if request.method == "POST":
        points = int(request.form["points"])
        discount = int(request.form["discount"])

        if user.reward_points < points:
            flash("Not enough points", "danger")
            return redirect(url_for("coupon"))

        # 🔐 Generate coupon code
        code = "CPN-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8))

        new_coupon = Coupon(
            code=code,
            discount_percent=discount,
            user_id=user.id,
            is_used=False,
            expires_at=datetime.utcnow() + timedelta(days=15),
            created_at=datetime.utcnow()
        )

        user.reward_points -= points

        db.session.add(new_coupon)
        db.session.commit()

        flash("Coupon generated successfully!", "success")
        return redirect(url_for("coupon"))

    # ✅ Fetch active coupons
    coupons = Coupon.query.filter(
        Coupon.user_id == user.id,
        Coupon.is_used == False,
        Coupon.expires_at > datetime.utcnow()
    ).order_by(Coupon.created_at.desc()).all()

    slabs = [
        {"points": 50, "discount": 5},
        {"points": 100, "discount": 10},
        {"points": 150, "discount": 15},
        {"points": 200, "discount": 20},
        {"points": 250, "discount": 25},
        {"points": 300, "discount": 30},
    ]

    return render_template(
        "coupon.html",
        user=user,
        coupons=coupons,
        slabs=slabs
    )

@app.route("/cleanup-expired-coupons")
def cleanup_expired_coupons():
    Coupon.query.filter(
        Coupon.expires_at < datetime.utcnow()
    ).update({"is_used": True})
    db.session.commit()
    return "Expired coupons cleaned"

# ================= TEST EMAIL =================
@app.route("/worker/apply-leave", methods=["POST"])
def apply_emergency_leave():
    if "user_id" not in session or session.get("user_role") != "worker":
        return redirect(url_for("login"))

    worker = User.query.get_or_404(session["user_id"])

    from_date = request.form["from_date"]
    to_date = request.form["to_date"]
    reason = request.form["reason"]

    # ❌ DATE VALIDATION
    if to_date < from_date:
        flash("Invalid leave date range", "danger")
        return redirect(url_for("worker_dashboard"))

    worker.status = "emergency_leave"
    worker.leave_from = from_date
    worker.leave_to = to_date
    worker.leave_reason = reason

    db.session.commit()

    flash("🚨 Emergency leave applied successfully", "success")
    return redirect(url_for("worker_dashboard"))


@app.route("/worker/toggle-status", methods=["POST"])
def toggle_worker_status():
    if "user_id" not in session or session.get("user_role") != "worker":
        return jsonify({"error": "Unauthorized"}), 401

    worker = User.query.get(session["user_id"])

    # 🚫 Cannot toggle during emergency leave
    if worker.status == "emergency_leave":
        return jsonify({"error": "On emergency leave"}), 403

    if worker.is_online:
        # GO OFFLINE
        worker.is_online = False
        worker.status = "offline"
    else:
        # GO ONLINE
        worker.is_online = True
        worker.status = "available"

    worker.last_seen = datetime.utcnow()
    db.session.commit()

    return jsonify({
        "status": worker.status,
        "is_online": worker.is_online
    })

# ================= CREATE ADMIN & WORKER =================
@app.route("/setup-staff")
def setup_staff():
    from werkzeug.security import generate_password_hash

    # 🔐 SECURITY CHECK (Change this key after use)
    secret_key = request.args.get("key")

    if secret_key != "sai123":
        return "Unauthorized ❌"

    created = []

    # ---------- CREATE ADMIN ----------
    if not User.query.filter_by(email="admin@gmail.com").first():
        admin = User(
            email="admin@gmail.com",
            password=generate_password_hash("admin123"),
            role="admin",
            is_online=False,
            balance=0,
            reward_points=0,
            fake_complaints=0,
            is_blocked=False
        )
        db.session.add(admin)
        created.append("Admin")
    else:
        created.append("Admin already exists")

    # ---------- CREATE WORKER ----------
    if not User.query.filter_by(email="worker@gmail.com").first():
        worker = User(
            email="worker@gmail.com",
            password=generate_password_hash("worker123"),
            role="worker",
            department="Electric",
            is_online=False,
            balance=0,
            reward_points=0,
            fake_complaints=0,
            is_blocked=False
        )
        db.session.add(worker)
        created.append("Worker")
    else:
        created.append("Worker already exists")

    db.session.commit()

    return " & ".join(created) + " ✅"
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
            body=f"""
                Your One-Time Password (OTP) is: {otp}

                ⏰ Valid for 5 minutes only.
                ❌ Do not share this OTP with anyone.

                If you did not request this, please ignore this email.
                """
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

    step = "form"

    # ---------- STEP 1: REGISTER FORM ----------
    if request.method == "POST" and "password" in request.form:

        email = request.form["email"]
        password = request.form["password"]
        confirm = request.form["confirm"]

        # password match
        if password != confirm:
            flash("Passwords do not match", "danger")
            return render_template("register.html", step="form")

        # already exists
        if User.query.filter_by(email=email).first():
            flash("Email already registered", "danger")
            return render_template("register.html", step="form")

        # generate OTP
        otp = generate_otp()

        session["reg_email"] = email
        session["reg_password"] = generate_password_hash(password)
        session["reg_otp"] = otp
        session["reg_otp_expiry"] = (
            datetime.utcnow() + timedelta(minutes=5)
        ).timestamp()

        # ✅ SEND EMAIL SAFELY (NO CRASH)
        try:
            send_email(
                to=email,
                subject="Verify Your Account",
                body=f"Your OTP is {otp}. Valid for 5 minutes."
            )
        except Exception as e:
            print("OTP email failed:", e)
            print("OTP is:", otp)

        flash("OTP sent to your email", "success")
        step = "otp"

    # ---------- STEP 2: OTP VERIFY ----------
    elif request.method == "POST" and "otp" in request.form:

        user_otp = request.form["otp"]

        if (
            user_otp != session.get("reg_otp")
            or datetime.utcnow().timestamp() > session.get("reg_otp_expiry", 0)
        ):
            flash("Invalid or expired OTP", "danger")
            step = "otp"
        else:
            # create user
            user = User(
                email=session["reg_email"],
                password=session["reg_password"]
            )
            db.session.add(user)
            db.session.commit()

            session.clear()
            flash("Account verified & created successfully", "success")
            return redirect(url_for("login"))

    return render_template("register.html", step=step)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(email=request.form["email"]).first()

        if not user or not check_password_hash(user.password, request.form["password"]):
            flash("Invalid credentials", "danger")
            return redirect(url_for("login"))

        if user.is_blocked:
            flash("🚫 Your account is blocked. Contact admin.", "danger")
            return redirect(url_for("login"))
        
        if user.role == "worker":
           user.is_online = 1
           user.last_seen = datetime.utcnow()
           db.session.commit()

        session.clear()
        session["user_id"] = user.id
        session["user_role"] = user.role

        if user.role == "worker":
            return redirect(url_for("worker_dashboard"))
        return redirect(url_for("dashboard"))

    return render_template("login.html")

@app.route("/logout")
def logout():
    uid = session.get("user_id")
    if uid:
        user = User.query.get(uid)
        if user and user.role == "worker":
            user.is_online = 0
            db.session.commit()

    session.clear()
    return redirect(url_for("login"))


# ================= COMPLAINT ================
@app.route("/index", methods=["GET", "POST"])
@login_and_block_guard()
def index():

    user = User.query.get_or_404(session["user_id"])  # logged-in user

    if request.method == "POST":

        # ================= MOBILE NUMBER =================
        mobile_number = request.form.get("mobile_number")
        if not mobile_number or not re.match(r"^[6-9]\d{9}$", mobile_number):
            flash("❌ Enter a valid 10-digit mobile number", "danger")
            return redirect(url_for("index"))

        # ================= LOCATION DATA (NEW) =================
        latitude = request.form.get("latitude")
        longitude = request.form.get("longitude")
        address = request.form.get("address")

        # ================= IMAGE CAPTURE =================
        image_path = None
        photo_data = request.form.get("photoData")

        if photo_data:
            try:
                _, encoded = photo_data.split(",", 1)
                img = base64.b64decode(encoded)
                name = datetime.now().strftime("%Y%m%d%H%M%S") + ".png"
                with open(os.path.join(UPLOAD_FOLDER, name), "wb") as f:
                    f.write(img)
                image_path = f"uploads/{name}"
            except Exception:
                flash("❌ Image processing failed", "danger")
                return redirect(url_for("index"))
        else:
            flash("❌ Photo with location is required", "danger")
            return redirect(url_for("index"))

        # ================= BASE PRICE =================
        BASE_PRICE = 500
        discount = 0

        # ================= POINTS DISCOUNT =================
        use_points = request.form.get("use_points")
        if use_points == "yes" and user.reward_points >= 10:
            discount += 50
            user.reward_points -= 10

        # ================= COUPON DISCOUNT =================
        coupon_code = request.form.get("coupon_code", "").strip()

        if coupon_code:
            coupon = Coupon.query.filter_by(
                user_id=user.id,
                code=coupon_code,
                is_used=False
            ).filter(
                Coupon.expires_at > datetime.utcnow()
            ).first()

            if coupon:
                discount += int(BASE_PRICE * (coupon.discount_percent / 100))
                coupon.is_used = True
            else:
                flash("❌ Invalid, expired, or already used coupon", "danger")

        # ================= FINAL AMOUNT =================
        final_amount = max(0, BASE_PRICE - discount)

        # ================= SAVE COMPLAINT (UPDATED) =================
        complaint = Complaint(
            category=request.form["category"],
            description=request.form["description"],
            mobile_number=mobile_number,
            image=image_path,
            user_id=user.id,
            amount=final_amount,

            # 🔥 LOCATION FIELDS ADDED
            latitude=latitude,
            longitude=longitude,
            address=address,

            status="Pending"
        )

        db.session.add(complaint)
        db.session.commit()

        flash(
            f"✅ Complaint submitted successfully.",
            "success"
        )
        return redirect(url_for("dashboard"))

    # ================= GET REQUEST =================
    return render_template("index.html", user=user)

# ================= DASHBOARD =================

@app.route("/")
def home():
    solutions = Solution.query.order_by(
        Solution.created_at.desc()
    ).limit(3).all()

    return render_template(
        "navbar.html",
        solutions=solutions
    )



@app.route("/worker/dashboard")
def worker_dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    auto_reset_leave()  # ✅ IMPORTANT

    worker = User.query.get_or_404(session["user_id"])

    notifications = Notification.query.filter_by(
        user_id=worker.id
    ).order_by(Notification.created_at.desc()).all()

    unread_count = Notification.query.filter_by(
        user_id=worker.id,
        is_read=False
    ).count()

    if worker.is_blocked:
        return render_template(
            "worker_dashboard.html",
            worker=worker,
            complaints=[],
            balance=worker.balance,
            completed_jobs=0,
            avg_rating=0,
            notifications=notifications,
            unread_count=unread_count,
            blocked=True
        )

    complaints = Complaint.query.filter_by(
        assigned_to=worker.id
    ).all()

    completed_jobs = Complaint.query.filter_by(
        assigned_to=worker.id,
        status="Approved"
    ).count()

    avg_rating = db.session.query(func.avg(Complaint.rating)) \
        .filter(
            Complaint.assigned_to == worker.id,
            Complaint.rating != None
        ).scalar()

    return render_template(
        "worker_dashboard.html",
        worker=worker,
        complaints=complaints,
        balance=worker.balance,
        completed_jobs=completed_jobs,
        avg_rating=round(avg_rating or 0, 1),
        notifications=notifications,
        unread_count=unread_count,
        blocked=False
    )

@app.route("/withdraw-history")
def withdraw_history():
    data = Withdrawal.query.filter_by(worker_id=session["user_id"]).all()
    return render_template("withdraw_history.html", data=data)



# ================= CHART API =================
@app.route("/api/dashboard-data")
def dashboard_data():
    status = dict(
        db.session.query(Complaint.status, func.count())
        .group_by(Complaint.status).all()
    )

    monthly = [0] * 12

    result = db.session.query(
        func.extract('month', Complaint.created_at).label("month"),
        func.count()
    ).group_by("month").all()

    for m, c in result:
        monthly[int(m) - 1] = c

    return jsonify({"status": status, "monthly": monthly})

@app.route("/admin/solutions")
def admin_solutions():
    if not is_admin():
        return redirect(url_for("login"))

    solutions = Solution.query.order_by(Solution.created_at.desc()).all()
    return render_template("admin_solutions.html", solutions=solutions)

@app.route("/solution", methods=["GET", "POST"])
@login_and_block_guard()
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

    return render_template("worker_salary.html", data=data )


@app.route("/worker/upload/<int:id>", methods=["POST"])
@login_and_block_guard()
def worker_upload(id):
    complaint = Complaint.query.get_or_404(id)
    if complaint.status in ["Completed", "Approved"]:
        flash("This task is locked.", "danger")
        return redirect(url_for("worker_dashboard"))

    file = request.files.get("work_image")
    if not file:
        flash("No file selected.", "warning")
        return redirect(url_for("worker_dashboard"))

    filename = secure_filename(file.filename)
    file.save(os.path.join("static/work", filename))

    complaint.work_image = f"work/{filename}"
    complaint.status = "Completed"

    db.session.commit()
    admin = User.query.filter_by(role="admin").first()

    create_notification(
    user_id=admin.id,
    title="✅ Work Completed",
    message=f"Complaint #{complaint.id} work completed. Review required."
)

    flash("Work submitted successfully.", "success")
    return redirect(url_for("worker_dashboard"))

@app.route("/admin/approve/<int:complaint_id>", methods=["POST"])
def admin_approve(complaint_id):
    if session.get("user_role") != "admin":
        return redirect(url_for("login"))

    complaint = Complaint.query.get_or_404(complaint_id)

    if complaint.status != "Completed":
        flash("Invalid approval request", "danger")
        return redirect(url_for("dashboard"))

    complaint.status = "Approved"
    complaint.approved_at = datetime.utcnow()

    user = User.query.get(complaint.user_id)
    if user:
        user.reward_points += 10

    worker = User.query.get(complaint.assigned_to)
    if worker:
        worker.status = "available"   # 🔓 FREE WORKER

        create_notification(
            user_id=worker.id,
            title="✅ Work Approved",
            message=f"Your work for Complaint #{complaint.id} has been approved.",
            email=worker.email
        )

    db.session.commit()
    flash("Complaint approved successfully", "success")
    return redirect(url_for("dashboard"))

@app.route("/api/workers/live-status")
def live_worker_status():

    # Only admin can see
    if session.get("user_role") != "admin":
        return jsonify([])

    workers = User.query.filter(
        User.role == "worker",
        User.is_online == True
    ).all()

    data = []
    for w in workers:
        data.append({
            "name": w.email,
            "status": w.status   # available / offline / busy
        })

    return jsonify(data)

@app.route("/admin/assign-worker/<int:id>", methods=["GET", "POST"])
def assign_worker(id):
    if session.get("user_role") != "admin":
        return redirect(url_for("login"))

    auto_reset_leave()

    complaint = Complaint.query.get_or_404(id)

    if request.method == "POST":
        worker_id = request.form.get("worker_id", type=int)

        worker = User.query.filter_by(
            id=worker_id,
            role="worker",
            status="available",
            is_online=True
        ).first()

        if not worker:
            flash("Invalid or unavailable worker", "danger")
            return redirect(url_for("dashboard"))

        complaint.assigned_to = worker.id
        complaint.status = "In Progress"

        worker.status = "busy"

        db.session.commit()
        flash("Worker assigned successfully", "success")
        return redirect(url_for("dashboard"))

    workers = User.query.filter_by(
        role="worker",
        status="available",
        is_online=True
    ).all()

    workers_by_dept = {}
    for w in workers:
        dept = w.department or "General"
        workers_by_dept.setdefault(dept, []).append(w)

    return render_template(
        "assign_worker.html",
        complaint=complaint,
        workers_by_dept=workers_by_dept
    )


@app.route("/admin/withdraw/reject/<int:id>", methods=["POST"])
def reject_withdraw(id):
    w = Withdrawal.query.get_or_404(id)

    if w.status != "Pending":
        flash("Already processed", "warning")
        return redirect(url_for("dashboard"))

    worker = User.query.get(w.worker_id)
    worker.balance += w.amount   # ✅ REFUND

    w.status = "Rejected"
    db.session.commit()

    flash("Withdraw rejected & refunded", "warning")
    return redirect(url_for("dashboard"))




@app.route("/admin/withdraw/pay/<int:id>", methods=["POST"])
def pay_withdraw(id):
    if not is_admin():
        return redirect(url_for("login"))

    w = Withdrawal.query.get_or_404(id)

    if w.status != "Approved":
        flash("Withdraw not approved yet", "warning")
        return redirect(url_for("dashboard"))

    w.status = "Paid"
    w.payout_ref = request.form["payout_ref"]
    w.payout_method = request.form["payout_method"]
    w.paid_at = datetime.utcnow()

    db.session.commit()

    flash("Payment marked as PAID", "success")
    return redirect(url_for("dashboard"))


@app.route('/withdraw', methods=['GET', 'POST'])
def withdraw():
    # 🔐 Worker login check
    if "user_id" not in session or session.get("user_role") != "worker":
        return redirect(url_for("login"))

    worker = User.query.get_or_404(session["user_id"])

    # 🚫 BANK DETAILS REQUIRED BEFORE WITHDRAW
    bank = BankDetail.query.filter_by(worker_id=worker.id).first()
    if not bank:
        flash("⚠️ Please add your bank details before requesting withdrawal.", "danger")
        return redirect(url_for("worker_bank_details"))

    if request.method == 'POST':
        try:
            amount = int(request.form['amount'])
        except (ValueError, TypeError):
            flash("Invalid amount entered", "danger")
            return redirect(url_for('withdraw'))

        MIN_WITHDRAW = 500
        MAX_WITHDRAW = 100000

        # ❌ Minimum limit
        if amount < MIN_WITHDRAW:
            flash(f"Minimum withdraw amount is ₹{MIN_WITHDRAW}", "danger")
            return redirect(url_for('withdraw'))

        # ❌ Maximum limit
        if amount > MAX_WITHDRAW:
            flash(f"Maximum withdraw allowed is ₹{MAX_WITHDRAW}", "danger")
            return redirect(url_for('withdraw'))

        # ❌ Balance check
        if amount > worker.balance:
            flash("Insufficient balance", "danger")
            return redirect(url_for('withdraw'))

        # ✅ Create withdraw request
        withdrawal = Withdrawal(
            worker_id=worker.id,
            amount=amount,
            status='Pending'
        )

        # 🔒 Hold balance until admin decision
        worker.balance -= amount

        db.session.add(withdrawal)
        db.session.commit()

        # 🔔 NOTIFY ADMIN (BEST PRACTICE)
        admin = User.query.filter_by(role="admin").first()
        if admin:
            create_notification(
                user_id=admin.id,
                title="💰 New Withdraw Request",
                message=f"Worker ID {worker.id} requested ₹{amount} withdrawal."
            )

        flash("Withdraw request submitted for admin approval", "success")
        return redirect(url_for('withdraw'))

    return render_template('withdraw.html', balance=worker.balance)




@app.route('/submit_rating/<int:complaint_id>', methods=['POST'])
def submit_rating(complaint_id):
    complaint = Complaint.query.get_or_404(complaint_id)

    if complaint.rating is not None:
        flash("Feedback already submitted.", "warning")
        return redirect(url_for("dashboard"))
  

    rating = int(request.form["rating"])
    feedback = request.form["feedback"]

    amount_map = {5: 500, 4: 400, 3: 300, 2: 200, 1: 50}
    amount = amount_map.get(rating, 0)

    worker = User.query.filter_by(
        id=complaint.assigned_to,
        role="worker"
    ).first()

    if not worker:
        flash("Worker not found.", "danger")
        return redirect(url_for("dashboard"))

    complaint.rating = rating
    complaint.feedback = feedback
    complaint.amount = amount

    # ✅ ADD SALARY ONLY IF ADMIN APPROVED & NOT PAID
    if complaint.status == "Approved" and not complaint.salary_paid:
        worker.balance += amount
        complaint.salary_paid = True

    db.session.commit()

    flash( "feedback is summited successfully!", "success")
    return redirect(url_for("dashboard"))

@app.route('/admin/withdrawals')
def admin_withdrawals():
    if not is_admin():
        return redirect(url_for('login'))

    withdrawals = db.session.query(
        Withdrawal, User, BankDetail
    ).join(
        User, Withdrawal.worker_id == User.id
    ).join(
        BankDetail, User.id == BankDetail.worker_id
    ).order_by(
        Withdrawal.created_at.desc()
    ).all()

    return render_template(
        'admin_withdrawals.html',
        withdrawals=withdrawals,
        is_admin=True
    )


@app.route("/admin/withdraw/approve/<int:id>", methods=["POST"])
def approve_withdraw(id):
    if not is_admin():
        return redirect(url_for("login"))

    w = Withdrawal.query.get_or_404(id)

    if w.status != "Pending":
        flash("Already processed", "warning")
        return redirect(url_for("dashboard"))

    w.status = "Approved"
    db.session.commit()

    flash("Withdraw approved", "success")
    return redirect(url_for("dashboard"))

@app.route("/api/withdraw/monthly")
def withdraw_monthly():
    if "user_id" not in session:
        return jsonify([0] * 12)

    worker_id = session["user_id"]

    result = db.session.query(
        func.extract('month', Withdrawal.created_at).label("month"),
        func.coalesce(func.sum(Withdrawal.amount), 0)
    ).filter(
        Withdrawal.worker_id == worker_id,
        Withdrawal.status == "Approved"
    ).group_by("month").all()

    data = [0] * 12
    for month, total in result:
        data[int(month) - 1] = int(total)

    return jsonify(data)
# ================= WORKER =================

@app.route("/worker/bank-details", methods=["GET", "POST"])
def worker_bank_details():
    if "user_id" not in session:
        return redirect(url_for("login"))

    worker_id = session["user_id"]

    if request.method == "POST":
        bank_name = request.form["bank_name"]
        account_number = request.form["account_number"]
        ifsc_code = request.form["ifsc_code"].upper()

        # ✅ IFSC VALIDATION
        if not re.match(r"^[A-Z]{4}0[A-Z0-9]{6}$", ifsc_code):
            flash("Invalid IFSC Code", "danger")
            return redirect(url_for("worker_bank_details"))

        # ✅ POSTGRESQL SAFE UPSERT
        db.session.execute(
            db.text("""
                INSERT INTO bank_details (worker_id, bank_name, account_number, ifsc_code)
                VALUES (:wid, :bank, :acc, :ifsc)
                ON CONFLICT (worker_id)
                DO UPDATE SET
                    bank_name = EXCLUDED.bank_name,
                    account_number = EXCLUDED.account_number,
                    ifsc_code = EXCLUDED.ifsc_code
            """),
            {
                "wid": worker_id,
                "bank": bank_name,
                "acc": account_number,
                "ifsc": ifsc_code
            }
        )

        db.session.commit()

        flash("Bank details saved successfully", "success")
        return redirect(url_for("worker_dashboard"))

    return render_template("worker_bank_details.html")
# ================= CREATE ADMIN & WORKER =================
@app.route("/fix-balance-once")
def fix_balance_once():
    complaints = Complaint.query.filter_by(
        status="Approved",
        salary_paid=False
    ).all()

    count = 0
    for c in complaints:
        worker = User.query.get(c.assigned_to)
        if worker and c.amount > 0:
            worker.balance += c.amount
            c.salary_paid = True
            count += 1

    db.session.commit()
    return f"Fixed {count} complaints"

@app.route("/worker/salary-pdf")
def salary_pdf():
    worker = User.query.get_or_404(session["user_id"])

    earned = worker.balance
    completed = Complaint.query.filter_by(
        assigned_to=worker.id,
        status="Approved"
    ).count()

    file_path = f"salary_{worker.id}.pdf"
    c = canvas.Canvas(file_path, pagesize=A4)

    c.setFont("Helvetica-Bold", 16)
    c.drawString(200, 800, "Salary Slip")

    c.setFont("Helvetica", 12)
    c.drawString(50, 760, f"Worker Email: {worker.email}")
    c.drawString(50, 730, f"Completed Jobs: {completed}")
    c.drawString(50, 700, f"Total Salary: ₹ {earned}")
    c.drawString(50, 670, f"Date: {datetime.now().strftime('%d %b %Y')}")

    c.save()

    return send_file(file_path, as_attachment=True)

@app.route("/admin/reject/<int:complaint_id>", methods=["POST"])
def admin_reject(complaint_id):
    if not is_admin():
        return redirect(url_for("login"))

    complaint = Complaint.query.get_or_404(complaint_id)

    # ❌ Already processed
    if complaint.status in ["Rejected", "Approved"]:
        flash("Complaint already processed", "warning")
        return redirect(url_for("dashboard"))

    reason = request.form.get("reason")

    # ✅ Reject complaint
    complaint.status = "Rejected"
    complaint.reject_reason = reason

    # 👤 Complaint owner
    user = User.query.get(complaint.user_id)

    # ⚠️ Increase fake count
    user.fake_complaints += 1

    # 🔔 Notify rejection
    create_notification(
        user_id=user.id,
        title="❌ Complaint Rejected",
        message=f"""
Your complaint #{complaint.id} was rejected as FAKE.

Reason:
{reason}

Warning:
You have {3 - user.fake_complaints} chance(s) left.
""",
        email=user.email
    )

    # 🚫 Block user if fake count >= 3
    if user.fake_complaints >= 3:
        user.is_blocked = True

        create_notification(
            user_id=user.id,
            title="🚫 Account Blocked",
            message="Your account has been BLOCKED due to repeated fake complaints.",
            email=user.email
        )

    db.session.commit()

    flash("Complaint rejected and user notified", "danger")
    return redirect(url_for("dashboard"))

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    auto_reset_leave()  # ✅ IMPORTANT

    user = User.query.get_or_404(session["user_id"])
    role = session.get("user_role")

    if role == "admin":
        complaints = Complaint.query.order_by(
            Complaint.created_at.desc()
        ).all()

        withdrawals = Withdrawal.query.order_by(
            Withdrawal.created_at.desc()
        ).all()

        return render_template(
            "dashboard.html",
            user=user,
            complaints=complaints,
            withdrawals=withdrawals,
            is_admin=True,
            is_user=False,
            blocked=False
        )

    if user.is_blocked:
        complaints = Complaint.query.filter(
            Complaint.user_id == user.id,
            Complaint.status != "Pending"
        ).all()

        return render_template(
            "dashboard.html",
            user=user,
            complaints=complaints,
            withdrawals=[],
            is_admin=False,
            is_user=True,
            blocked=True
        )

    complaints = Complaint.query.filter_by(
        user_id=user.id
    ).order_by(Complaint.created_at.desc()).all()

    return render_template(
        "dashboard.html",
        user=user,
        complaints=complaints,
        withdrawals=[],
        is_admin=False,
        is_user=True,
        blocked=False
    )

@app.route("/notifications/read")
def mark_notifications_read():
    if "user_id" not in session:
        return redirect(url_for("login"))

    Notification.query.filter_by(
        user_id=session["user_id"],
        is_read=False
    ).update({"is_read": True})

    db.session.commit()
    return redirect(url_for("worker_dashboard"))

@app.route("/notifications")
def notifications():
    if "user_id" not in session:
        return redirect(url_for("login"))

    notes = Notification.query.filter_by(
        user_id=session["user_id"]
    ).order_by(Notification.created_at.desc()).all()

    # mark all as read
    Notification.query.filter_by(
        user_id=session["user_id"],
        is_read=False
    ).update({"is_read": True})

    db.session.commit()

    return render_template("notifications.html", notifications=notes)

if __name__ == "__main__":
    app.run()


