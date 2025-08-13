# 🎫 Flask + SQLite Ticketing System

A simple, production-ready starter for a role‑based ticketing system with **User**, **Support Agent**, and **Admin** roles.

## ✅ Features

- Authentication (login/logout) and **role-based access**.
- **User Dashboard**: create tickets, comment, see history, upload attachments, track statuses.
- **Agent Dashboard**: sees **only tickets assigned to them**; change status, comment, reassign (if currently assigned).
- **Admin Panel**: manage users and roles, view all tickets, force reassign, override statuses.
- Ticket lifecycle: **Open → In Progress → Resolved → Closed**.
- Comments with timestamps & author, full ticket **history** audit.
- **Search & Filter** by subject, status, priority.
- **Priorities**: Low, Medium, High, Urgent.
- **File attachments** (16MB limit; common formats allowed).
- **Email notifications** (optional via SMTP) on creation/assignment/status change/comments (mocked to console by default).
- **Rate resolution** (1–5 stars) once ticket is Resolved/Closed.

## 🧰 Tech Stack

- Backend: **Flask**, **Flask-SQLAlchemy**, SQLite
- Frontend: HTML, CSS (vanilla), minimal JS (not required)

## 🚀 Quick Start

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open http://localhost:5000

### Demo Accounts

- **Admin**: `admin@example.com` / `admin123`
- **Agent**: `agent@example.com` / `agent123`
- **User**: `user@example.com` / `user123`

> The database is created/seeded automatically on first run. You can also run:  
> `flask --app app.py init-db`

## 📂 Project Structure

```
ticketing-system/
├── app.py
├── config.py
├── requirements.txt
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── dashboard_user.html
│   ├── dashboard_agent.html
│   ├── dashboard_admin.html
│   ├── manage_users.html
│   ├── ticket_new.html
│   └── ticket_view.html
├── static/
│   └── styles.css
└── uploads/        # file uploads are stored here
```

## 🔐 Roles & Access Control

- **Admin**: manage users, view/override all tickets, assign/reassign tickets.
- **Agent**: sees **only their assigned tickets**, can change status, comment, reassign tickets **they are assigned to**.
- **User**: create/manage **their own tickets**, can set status to Resolved/Closed for their tickets, add comments, upload files, and rate the resolution.

#  Note
I have not created the task on:
● Backend:
○ Java/Kotlin
○ Spring Boot
○ Postgresql
● Frontend:
○ Next.js (React-based framework)

I am trying to learn the above tech stack that's why I am doing the task in flask and Sqlite.


```

