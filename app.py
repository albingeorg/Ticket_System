\
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os, re, smtplib, ssl, functools

from config import Config

ALLOWED_EXTENSIONS = {"png","jpg","jpeg","gif","pdf","txt","log","zip","doc","docx"}

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)

# -----------------------------
# Models
# -----------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")  # admin | agent | user

    tickets_owned = db.relationship("Ticket", backref="owner", foreign_keys="Ticket.owner_id", lazy=True)
    tickets_assigned = db.relationship("Ticket", backref="assignee", foreign_keys="Ticket.assignee_id", lazy=True)

    def set_password(self, pwd):
        self.password_hash = generate_password_hash(pwd)

    def check_password(self, pwd):
        return check_password_hash(self.password_hash, pwd)

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    priority = db.Column(db.String(20), nullable=False, default="Low")  # Low, Medium, High, Urgent
    status = db.Column(db.String(20), nullable=False, default="Open")   # Open, In Progress, Resolved, Closed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    assignee_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

    comments = db.relationship("Comment", backref="ticket", cascade="all, delete", lazy=True)
    attachments = db.relationship("Attachment", backref="ticket", cascade="all, delete", lazy=True)
    history = db.relationship("History", backref="ticket", cascade="all, delete", lazy=True)
    rating = db.relationship("Rating", backref="ticket", uselist=False, cascade="all, delete", lazy=True)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("ticket.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User")

class Attachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("ticket.id"), nullable=False)
    filename = db.Column(db.String(255), nullable=False)       # stored filename
    original_name = db.Column(db.String(255), nullable=False)  # original uploaded name
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("ticket.id"), nullable=False)
    action = db.Column(db.String(255), nullable=False)   # "status: Open -> In Progress", "assigned: user -> agent"
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    performed_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    performed_by = db.relationship("User")

class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("ticket.id"), nullable=False, unique=True)
    stars = db.Column(db.Integer, nullable=False)  # 1..5
    feedback = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# -----------------------------
# Helpers & Decorators
# -----------------------------
def init_db():
    db.create_all()
    # seed one admin, one agent for demo if not exists
    if not User.query.filter_by(email="admin@example.com").first():
        admin = User(name="Admin", email="admin@example.com", role="admin")
        admin.set_password("admin123")
        db.session.add(admin)
    if not User.query.filter_by(email="agent@example.com").first():
        agent = User(name="Agent", email="agent@example.com", role="agent")
        agent.set_password("agent123")
        db.session.add(agent)
    if not User.query.filter_by(email="user@example.com").first():
        user = User(name="User", email="user@example.com", role="user")
        user.set_password("user123")
        db.session.add(user)
    db.session.commit()

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return User.query.get(uid)

def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped

def role_required(*roles):
    def decorator(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user or user.role not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def record_history(ticket, action, performer):
    h = History(ticket_id=ticket.id, action=action, performed_by_id=performer.id)
    db.session.add(h)
    db.session.commit()

def send_email_notification(to_email, subject, body):
    # Optional SMTP; if not configured, just print to console
    if not app.config.get("MAIL_SERVER") or not app.config.get("MAIL_USERNAME"):
        print("[EMAIL MOCK] To:", to_email)
        print("Subject:", subject)
        print(body)
        return
    message = f"From: {app.config.get('MAIL_DEFAULT_SENDER')}\r\nTo: {to_email}\r\nSubject: {subject}\r\n\r\n{body}"
    context = ssl.create_default_context()
    with smtplib.SMTP(app.config["MAIL_SERVER"], app.config["MAIL_PORT"]) as server:
        if app.config["MAIL_USE_TLS"]:
            server.starttls(context=context)
        server.login(app.config["MAIL_USERNAME"], app.config["MAIL_PASSWORD"])
        server.sendmail(app.config.get("MAIL_DEFAULT_SENDER"), [to_email], message)

# -----------------------------
# Auth Routes
# -----------------------------
@app.route("/")
def index():
    if current_user():
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session["user_id"] = user.id
            session["role"] = user.role
            flash("Logged in successfully.", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid credentials.", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))

# -----------------------------
# Dashboards
# -----------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    if user.role == "admin":
        return redirect(url_for("admin_dashboard"))
    elif user.role == "agent":
        return redirect(url_for("agent_dashboard"))
    else:
        return redirect(url_for("user_dashboard"))

@app.route("/dashboard/user")
@login_required
@role_required("user")
def user_dashboard():
    user = current_user()
    q = request.args.get("q","").strip()
    status = request.args.get("status","")
    priority = request.args.get("priority","")
    tickets = Ticket.query.filter_by(owner_id=user.id)
    if q:
        tickets = tickets.filter(Ticket.subject.ilike(f"%{q}%"))
    if status:
        tickets = tickets.filter_by(status=status)
    if priority:
        tickets = tickets.filter_by(priority=priority)
    tickets = tickets.order_by(Ticket.updated_at.desc()).all()
    return render_template("dashboard_user.html", user=user, tickets=tickets)

@app.route("/dashboard/agent")
@login_required
@role_required("agent")
def agent_dashboard():
    user = current_user()
    q = request.args.get("q","").strip()
    status = request.args.get("status","")
    priority = request.args.get("priority","")
    # IMPORTANT: Agent sees only tickets assigned to them
    tickets = Ticket.query.filter_by(assignee_id=user.id)
    if q:
        tickets = tickets.filter(Ticket.subject.ilike(f"%{q}%"))
    if status:
        tickets = tickets.filter_by(status=status)
    if priority:
        tickets = tickets.filter_by(priority=priority)
    tickets = tickets.order_by(Ticket.updated_at.desc()).all()
    return render_template("dashboard_agent.html", user=user, tickets=tickets)

@app.route("/dashboard/admin")
@login_required
@role_required("admin")
def admin_dashboard():
    user = current_user()
    q = request.args.get("q","").strip()
    status = request.args.get("status","")
    priority = request.args.get("priority","")
    tickets = Ticket.query
    if q:
        tickets = tickets.filter(Ticket.subject.ilike(f"%{q}%"))
    if status:
        tickets = tickets.filter_by(status=status)
    if priority:
        tickets = tickets.filter_by(priority=priority)
    tickets = tickets.order_by(Ticket.updated_at.desc()).all()
    return render_template("dashboard_admin.html", user=user, tickets=tickets, users=User.query.all())

# -----------------------------
# Ticket CRUD & Actions
# -----------------------------
@app.route("/tickets/new", methods=["GET","POST"])
@login_required
@role_required("user","admin","agent")
def new_ticket():
    user = current_user()
    if request.method == "POST":
        subject = request.form.get("subject","").strip()
        description = request.form.get("description","").strip()
        priority = request.form.get("priority","Low")
        assignee_id = request.form.get("assignee_id") if user.role in ("admin",) else None

        if not subject or not description:
            flash("Subject and description are required.", "danger")
            return render_template("ticket_new.html", user=user, users=User.query.filter_by(role="agent").all())

        ticket = Ticket(subject=subject, description=description, priority=priority, owner_id=user.id)
        if assignee_id:
            agent = User.query.get(int(assignee_id))
            if agent and agent.role == "agent":
                ticket.assignee_id = agent.id
        db.session.add(ticket)
        db.session.commit()
        record_history(ticket, "Ticket created", user)
        if ticket.assignee_id:
            send_email_notification(ticket.assignee.email, f"Ticket #{ticket.id} assigned to you", f"Subject: {ticket.subject}")
        flash("Ticket created.", "success")
        return redirect(url_for("view_ticket", ticket_id=ticket.id))

    return render_template("ticket_new.html", user=user, users=User.query.filter_by(role="agent").all())

def user_can_view_ticket(user, ticket):
    if user.role == "admin":
        return True
    if user.role == "user":
        return ticket.owner_id == user.id
    if user.role == "agent":
        return ticket.assignee_id == user.id
    return False

@app.route("/tickets/<int:ticket_id>", methods=["GET","POST"])
@login_required
def view_ticket(ticket_id):
    user = current_user()
    ticket = Ticket.query.get_or_404(ticket_id)
    if not user_can_view_ticket(user, ticket):
        abort(403)

    # Add comment
    if request.method == "POST" and "comment" in request.form:
        content = request.form.get("comment","").strip()
        if content:
            c = Comment(ticket_id=ticket.id, user_id=user.id, content=content)
            db.session.add(c)
            db.session.commit()
            record_history(ticket, f"Comment added", user)
            flash("Comment added.", "success")
            # notify owner/assignee
            notify_list = set()
            if ticket.owner and ticket.owner.email:
                notify_list.add(ticket.owner.email)
            if ticket.assignee and ticket.assignee.email:
                notify_list.add(ticket.assignee.email)
            for email in notify_list:
                send_email_notification(email, f"New comment on Ticket #{ticket.id}", content)
            return redirect(url_for("view_ticket", ticket_id=ticket.id))

    return render_template("ticket_view.html", user=user, ticket=ticket, agents=User.query.filter_by(role="agent").all())

@app.route("/tickets/<int:ticket_id>/status", methods=["POST"])
@login_required
def update_status(ticket_id):
    user = current_user()
    ticket = Ticket.query.get_or_404(ticket_id)
    if not user_can_view_ticket(user, ticket):
        abort(403)

    new_status = request.form.get("status")
    allowed_statuses = ["Open","In Progress","Resolved","Closed"]
    if new_status not in allowed_statuses:
        flash("Invalid status.", "danger")
        return redirect(url_for("view_ticket", ticket_id=ticket.id))

    # Only admins and assigned agents can change status; owners can mark Resolved/Closed on their own tickets
    if user.role == "admin" or (user.role == "agent" and ticket.assignee_id == user.id) or (user.role == "user" and ticket.owner_id == user.id and new_status in ["Resolved","Closed"]):
        old = ticket.status
        ticket.status = new_status
        db.session.commit()
        record_history(ticket, f"status: {old} -> {new_status}", user)

        # notify interested parties
        notify_list = set(filter(None, [ticket.owner.email if ticket.owner else None, ticket.assignee.email if ticket.assignee else None]))
        for email in notify_list:
            send_email_notification(email, f"Ticket #{ticket.id} status updated", f"{old} -> {new_status}")
        flash("Status updated.", "success")
    else:
        flash("Not allowed to change status.", "danger")
    return redirect(url_for("view_ticket", ticket_id=ticket.id))

@app.route("/tickets/<int:ticket_id>/assign", methods=["POST"])
@login_required
def assign_ticket(ticket_id):
    user = current_user()
    ticket = Ticket.query.get_or_404(ticket_id)
    assignee_id = request.form.get("assignee_id", type=int)
    target = User.query.get(assignee_id) if assignee_id else None
    # Only admin can force assign. Users can reassign if role permits -> assume only admin or current assignee can reassign
    if user.role not in ("admin","agent"):
        abort(403)
    if user.role == "agent" and ticket.assignee_id != user.id:
        abort(403)
    if not target or target.role != "agent":
        flash("Invalid assignee.", "danger")
        return redirect(url_for("view_ticket", ticket_id=ticket.id))

    old = ticket.assignee.name if ticket.assignee else "Unassigned"
    ticket.assignee_id = target.id
    db.session.commit()
    record_history(ticket, f"assigned: {old} -> {target.name}", user)
    if target.email:
        send_email_notification(target.email, f"Ticket #{ticket.id} assigned to you", f"Subject: {ticket.subject}")
    flash("Ticket reassigned.", "success")
    return redirect(url_for("view_ticket", ticket_id=ticket.id))

# -----------------------------
# Attachments
# -----------------------------
@app.route("/tickets/<int:ticket_id>/upload", methods=["POST"])
@login_required
def upload_file(ticket_id):
    user = current_user()
    ticket = Ticket.query.get_or_404(ticket_id)
    if not user_can_view_ticket(user, ticket):
        abort(403)
    file = request.files.get("file")
    if not file or file.filename == "":
        flash("No file selected.", "warning")
        return redirect(url_for("view_ticket", ticket_id=ticket.id))
    if not allowed_file(file.filename):
        flash("File type not allowed.", "danger")
        return redirect(url_for("view_ticket", ticket_id=ticket.id))
    fname = secure_filename(file.filename)
    # make unique filename
    base, ext = os.path.splitext(fname)
    stored = f"{base}_{int(datetime.utcnow().timestamp())}{ext}"
    file.save(os.path.join(app.config["UPLOAD_FOLDER"], stored))
    a = Attachment(ticket_id=ticket.id, filename=stored, original_name=fname)
    db.session.add(a)
    db.session.commit()
    record_history(ticket, f"attachment uploaded: {fname}", user)
    flash("File uploaded.", "success")
    return redirect(url_for("view_ticket", ticket_id=ticket.id))

@app.route("/attachments/<int:attachment_id>/download")
@login_required
def download_attachment(attachment_id):
    a = Attachment.query.get_or_404(attachment_id)
    ticket = a.ticket
    if not user_can_view_ticket(current_user(), ticket):
        abort(403)
    return send_from_directory(app.config["UPLOAD_FOLDER"], a.filename, as_attachment=True, download_name=a.original_name)

# -----------------------------
# Rating
# -----------------------------
@app.route("/tickets/<int:ticket_id>/rate", methods=["POST"])
@login_required
@role_required("user")
def rate_ticket(ticket_id):
    user = current_user()
    ticket = Ticket.query.get_or_404(ticket_id)
    if ticket.owner_id != user.id:
        abort(403)
    stars = request.form.get("stars", type=int)
    feedback = request.form.get("feedback","").strip()
    if stars < 1 or stars > 5:
        flash("Invalid rating.", "danger")
        return redirect(url_for("view_ticket", ticket_id=ticket.id))
    if ticket.rating:
        ticket.rating.stars = stars
        ticket.rating.feedback = feedback
    else:
        r = Rating(ticket_id=ticket.id, stars=stars, feedback=feedback)
        db.session.add(r)
    db.session.commit()
    record_history(ticket, f"rating submitted: {stars} star(s)", user)
    flash("Thanks for your feedback!", "success")
    return redirect(url_for("view_ticket", ticket_id=ticket.id))

# -----------------------------
# Admin: User Management
# -----------------------------
@app.route("/admin/users")
@login_required
@role_required("admin")
def manage_users():
    return render_template("manage_users.html", user=current_user(), users=User.query.all())

@app.route("/admin/users/add", methods=["POST"])
@login_required
@role_required("admin")
def add_user():
    name = request.form.get("name","").strip()
    email = request.form.get("email","").strip().lower()
    role = request.form.get("role","user")
    password = request.form.get("password","").strip()
    if not name or not email or not password:
        flash("All fields are required.", "danger")
        return redirect(url_for("manage_users"))
    if role not in ("admin","agent","user"):
        role = "user"
    if User.query.filter_by(email=email).first():
        flash("Email already exists.", "danger")
        return redirect(url_for("manage_users"))
    u = User(name=name, email=email, role=role)
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    flash("User created.", "success")
    return redirect(url_for("manage_users"))

@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@login_required
@role_required("admin")
def delete_user(user_id):
    if current_user().id == user_id:
        flash("You cannot delete yourself.", "danger")
        return redirect(url_for("manage_users"))
    u = User.query.get_or_404(user_id)
    db.session.delete(u)
    db.session.commit()
    flash("User deleted.", "info")
    return redirect(url_for("manage_users"))

# -----------------------------
# Static routes
# -----------------------------
@app.route("/uploads/<path:filename>")
@login_required
def uploaded_file(filename):
    # Not listing browsing; rely on direct IDs for download
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# -----------------------------
# CLI bootstrap
# -----------------------------
@app.cli.command("init-db")
def cli_init_db():
    init_db()
    print("Database initialized with demo users.")

if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(host="0.0.0.0", port=5000, debug=True )
