import os
import io
import json
import bcrypt
import configparser
import csv
import smtplib
import openpyxl
import secrets
from datetime import datetime, timedelta
from flask_socketio import SocketIO, emit # Add this import
from functools import wraps
import json
from flask import jsonify



from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, session, send_file, abort, \
    render_template_string
from sqlalchemy import create_engine, text
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Place this near the top of your app.py, e.g., after the imports.
import math

class Pagination:
    """A simple pagination object for raw SQLAlchemy results."""
    def __init__(self, page, per_page, total, items):
        self.page = page
        self.per_page = per_page
        self.total = total
        self.items = items
        self.pages = math.ceil(total / per_page) if total > 0 else 1
        self.has_prev = self.page > 1
        self.prev_num = self.page - 1 if self.has_prev else None
        self.has_next = self.page < self.pages
        self.next_num = self.page + 1 if self.has_next else None

# --- Configuration & Setup ---
app = Flask(__name__)
app.jinja_env.filters['from_json'] = json.loads

app.secret_key = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*") # Initialize SocketIO

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
config = configparser.ConfigParser()
config.read(os.path.join(BASE_DIR, 'config.ini'))

try:
    LIVE_DB_URI = config.get('Database', 'live_db_uri', fallback=None)
    ARCHIVE_DB_URI = config.get('Database', 'archive_db_uri', fallback=None)
except Exception:
    LIVE_DB_URI = None
    ARCHIVE_DB_URI = None

engine = create_engine(LIVE_DB_URI, pool_pre_ping=True) if LIVE_DB_URI else None
archive_engine = create_engine(ARCHIVE_DB_URI, pool_pre_ping=True) if ARCHIVE_DB_URI else None


# ==========================================
# DYNAMIC ROLE PERMISSIONS (Helper & Context)
# ==========================================
def get_role_permissions():
    """Fetches dynamic menu permissions from the database."""
    if not engine:
        return {}
    try:
        with engine.connect() as c:
            res = c.execute(
                text("SELECT setting_value FROM system_settings WHERE setting_key = 'role_permissions'")).scalar()
            if res:
                return json.loads(res)
    except Exception as e:
        print(f"Error loading permissions: {e}")

    # DEFAULT fallback if the database is empty
    return {
        "menu_directory": ["manager", "management", "admin", "super admin", "it support"],
        "menu_ier_b": ["manager", "management", "admin", "super admin", "it support"],
        "menu_admin_tools": ["management", "admin", "super admin"]
    }


@app.context_processor
def inject_dynamic_roles():
    if 'user_role' in session:
        role = session.get('user_role', '').lower()
        perms = get_role_permissions()  # Fetches JSON from DB

        return dict(
            current_user_role=role,
            can_see_directory=role in perms.get('menu_directory', []) or role == 'super admin',
            can_see_ier_b=role in perms.get('menu_ier_b', []) or role == 'super admin',
            can_see_admin_tools=role in perms.get('menu_admin_tools', []) or role == 'super admin',
            # This line now looks at the Database settings:
            can_see_ier_hub=role in perms.get('menu_ier_hub', []) or role == 'super admin',
            can_see_it_projects = role in perms.get('menu_it_projects', []) or role == 'super admin'
        )
    return dict(current_user_role=None, can_see_directory=False, can_see_ier_b=False, can_see_admin_tools=False,
                can_see_ier_hub=False)
# ==========================================
# HELPERS & DECORATORS
# ==========================================

def send_notification(subject, recipient, body):
    """Sends email using settings from the database."""
    if not engine: return
    with engine.connect() as c:
        res = c.execute(text("SELECT setting_key, setting_value FROM system_settings")).fetchall()
        st = {k: v for k, v in res}

    if not st.get('smtp_server'): return

    try:
        msg = MIMEMultipart()
        msg['From'] = st.get('sender_email')
        msg['To'] = recipient
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(st.get('smtp_server'), int(st.get('smtp_port', 587)))
        server.starttls()
        server.login(st.get('sender_email'), st.get('sender_password'))
        server.sendmail(st.get('sender_email'), recipient, msg.as_string())
        server.quit()
    except Exception as e:
        print(f"Mail Error: {e}")


def log_audit(username, action, target_type=None, target_id=None, details=None):
    """Comprehensive logging for the Audit Trail, including IP Tracking."""
    if not engine: return
    try:
        ip_addr = request.remote_addr
        detail_dict = {"details": details} if details else {}
        if ip_addr:
            detail_dict['ip_address'] = ip_addr

        detail_str = json.dumps(detail_dict) if detail_dict else None

        with engine.begin() as conn:
            conn.execute(
                text("""INSERT INTO audit_log (username, action, target_type, target_id, details)
                        VALUES (:un, :act, :tt, :ti, :det)"""),
                {"un": username, "act": action, "tt": target_type, "ti": str(target_id) if target_id else None,
                 "det": detail_str}
            )
    except Exception as e:
        print(f"Audit Log Error: {e}")


def get_due_date(ticket_type, priority):
    """SLA Calculator querying the database policies."""
    if not engine: return datetime.now() + timedelta(days=3)
    try:
        with engine.connect() as conn:
            res = conn.execute(
                text("SELECT resolve_in_hours FROM sla_policies WHERE ticket_type = :tt AND priority = :p"),
                {"tt": ticket_type, "p": priority}
            ).scalar()

            if res is None:
                hours = {"Low": 168, "Medium": 72, "High": 24, "Urgent": 8}.get(priority, 72)
            else:
                hours = res

            return datetime.now() + timedelta(hours=hours)
    except Exception as e:
        print(f"SLA Calculation Error: {e}")
        return datetime.now() + timedelta(days=3)


def login_required(f):
    def wrap(*args, **kwargs):
        # Redirect to the Gateway PIN page if not logged in
        if 'username' not in session: return redirect(url_for('gateway'))
        return f(*args, **kwargs)

    wrap.__name__ = f.__name__
    return wrap


from functools import wraps


# ... (other code) ...

def management_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        role = session.get('user_role', '').lower()
        management_roles = ['management', 'admin', 'super admin', 'it support']

        if role not in management_roles:
            flash("Access Denied: Management level required to view this function.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)

    return wrap


def manager_or_management_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        role = session.get('user_role', '').lower()
        allowed_roles = ['manager', 'management', 'admin', 'super admin', 'it support']

        if role not in allowed_roles:
            flash("Access Denied: Manager level or higher required.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)

    return wrap


def admin_required(f):
    def wrap(*args, **kwargs):
        if session.get('user_role', '').lower() not in ['admin', 'super admin', 'it support']:
            flash("Access Denied: Management level required.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)


    wrap.__name__ = f.__name__
    return wrap




# ==========================================
# CONTEXT PROCESSOR FOR UI MENUS
# ==========================================
@app.context_processor
def inject_roles():
    """
    This makes these variables automatically available in EVERY HTML template.
    You can use them to hide/show side menu items.
    """
    if 'user_role' in session:
        role = session.get('user_role', '').lower()
        # Group legacy roles with the new 'management' role
        management_roles = ['management', 'super admin', 'admin', 'it support']

        return dict(
            is_user=role == 'user',
            is_manager=role == 'manager',
            is_management=role in management_roles,
            current_role=role
        )
    return dict(is_user=False, is_manager=False, is_management=False, current_role=None)

# --- File Serving ---
@app.route('/file/<table_name>/<int:id>/<column>')
@login_required
def serve_file(table_name, id, column):
    allowed_tables = {'tickets': 'ticket_id', 'ier_forms_a': 'id', 'ier_forms_b': 'id'}
    if table_name not in allowed_tables:
        abort(403)

    pk_col = allowed_tables[table_name]

    # Logic: If column is 'file_ier', the name column is 'file_ier_name'
    # Special case for ier_forms_a where column is 'file_blob' and name is 'file_name'
    name_column = "file_name" if column == "file_blob" else f"{column}_name"

    with engine.connect() as conn:
        res = conn.execute(text(f"SELECT {column}, {name_column} FROM {table_name} WHERE {pk_col} = :id"),
                           {"id": id}).fetchone()

        if not res or not res[0]:
            abort(404)

        file_blob = res[0]
        # Use saved filename, or fallback to a generic name if missing
        file_name = res[1] if res[1] else f"attachment_{id}.bin"

        return send_file(
            io.BytesIO(bytes(file_blob)),
            download_name=file_name,
            as_attachment=True
        )


@app.route('/signature/<int:user_id>')
@login_required
def serve_signature(user_id):
    """Serves the signature image for a given user."""
    with engine.connect() as conn:
        res = conn.execute(text("SELECT signature_blob FROM users WHERE user_id = :id"), {"id": user_id}).scalar()
        if not res:
            abort(404)
        return send_file(io.BytesIO(res), mimetype='image/png')


# ==========================================
# 1. AUTHENTICATION & SECURE GATEWAY
# ==========================================

COMPANY_PIN = "8899"  # The PIN your employees will use


@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('gateway'))


@app.route('/portal', methods=['GET', 'POST'])
def gateway():
    if request.method == 'POST':
        if request.form.get('gateway_code') == COMPANY_PIN:
            encrypted_token = secrets.token_urlsafe(32)
            session['active_auth_token'] = encrypted_token
            return redirect(url_for('secure_login', token=encrypted_token))
        else:
            flash("Invalid Gateway PIN. Access Denied.", "danger")

    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>MBPI Secure Gateway</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&display=swap" rel="stylesheet">
        <style>
            :root { 
                --primary: #002e5d; 
                --accent: #d71921; 
                --glass: rgba(255, 255, 255, 0.9);
            }

            body { 
                font-family: 'Plus Jakarta Sans', sans-serif; 
                height: 100vh; margin: 0; 
                display: flex; align-items: center; justify-content: center;
                background-color: #f4f7f9;
                overflow: hidden;
            }

            /* Consistent V2 Mesh Background */
            .mesh-bg { 
                position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: -1; 
                background-image: 
                    radial-gradient(at 0% 0%, rgba(0, 46, 93, 0.05) 0px, transparent 50%), 
                    radial-gradient(at 100% 100%, rgba(215, 25, 33, 0.03) 0px, transparent 50%),
                    radial-gradient(at 100% 0%, rgba(0, 46, 93, 0.05) 0px, transparent 50%);
            }

            .gateway-card {
                width: 100%;
                max-width: 420px;
                background: var(--glass);
                backdrop-filter: blur(15px);
                border-radius: 32px;
                border: 1px solid rgba(255,255,255,0.7);
                box-shadow: 0 30px 60px rgba(0,0,0,0.1);
                overflow: hidden;
                transition: transform 0.3s ease;
            }

            .gateway-header {
                background: linear-gradient(135deg, var(--primary) 0%, #001a35 100%);
                padding: 40px 20px;
                text-align: center;
                color: white;
            }

            .lock-icon-wrapper {
                width: 64px; height: 64px;
                background: rgba(255,255,255,0.1);
                border: 1px solid rgba(255,255,255,0.2);
                border-radius: 20px;
                display: flex; align-items: center; justify-content: center;
                margin: 0 auto 20px;
                font-size: 24px;
                position: relative;
            }

            .lock-icon-wrapper::after {
                content: ''; position: absolute; width: 100%; height: 100%;
                border-radius: 20px; box-shadow: 0 0 20px rgba(255,255,255,0.2);
                animation: pulse 2s infinite;
            }

            @keyframes pulse { 0% { transform: scale(1); opacity: 0.5; } 50% { transform: scale(1.1); opacity: 0; } 100% { transform: scale(1); opacity: 0.5; } }

            .gateway-body { padding: 40px; text-align: center; }

            /* Digital Slot PIN Input */
            .secure-input {
                -webkit-text-security: disc;
                font-size: 2.5rem; 
                letter-spacing: 15px; 
                border-radius: 20px; 
                background: #ffffff; 
                border: 2px solid #e2e8f0; 
                padding: 15px;
                text-align: center;
                color: var(--primary);
                font-weight: 800;
                transition: all 0.3s ease;
                box-shadow: inset 0 2px 4px rgba(0,0,0,0.02);
            }

            .secure-input:focus {
                border-color: var(--primary);
                box-shadow: 0 0 0 5px rgba(0, 46, 93, 0.05);
                outline: none;
            }

            .shake { animation: shake 0.5s cubic-bezier(.36,.07,.19,.97) both; }
            @keyframes shake { 10%, 90% { transform: translate3d(-1px, 0, 0); } 20%, 80% { transform: translate3d(2px, 0, 0); } 30%, 50%, 70% { transform: translate3d(-4px, 0, 0); } 40%, 60% { transform: translate3d(4px, 0, 0); } }

            .status-msg { font-size: 0.8rem; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; color: #94a3b8; margin-top: 20px; }

            .alert-v2 {
                background: #fee2e2; color: #b91c1c;
                border-radius: 14px; padding: 12px;
                font-size: 0.85rem; font-weight: 700;
                margin-top: 20px; border: 1px solid #fecaca;
            }
        </style>
    </head>
    <body>
        <div class="mesh-bg"></div>

        <div class="gateway-card {% if get_flashed_messages() %}shake{% endif %}">
            <div class="gateway-header">
                <div class="lock-icon-wrapper">
                    <i class="fa-solid fa-shield-halved"></i>
                </div>
                <h4 class="fw-800 m-0">MBPI Secure Gateway</h4>
                <p class="small opacity-75 mt-2 mb-0">Identity Verification Required</p>
            </div>

            <div class="gateway-body">
                <form method="POST" id="gatewayForm">
                    <label class="small fw-800 text-muted text-uppercase mb-3 d-block" style="letter-spacing: 1px;">Enter Company Access PIN</label>
                    <input type="text" 
                           id="pinInput"
                           name="gateway_code" 
                           autocomplete="off" 
                           inputmode="numeric"
                           maxlength="4"
                           autofocus
                           class="form-control secure-input" 
                           placeholder="••••" 
                           required>

                    <div class="status-msg" id="statusMsg">Waiting for input...</div>
                    <button type="submit" class="d-none"></button>
                </form>

                {% with messages = get_flashed_messages() %}
                    {% if messages %}
                        {% for message in messages %}
                            <div class="alert-v2"><i class="fa-solid fa-triangle-exclamation me-2"></i>{{ message }}</div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
            </div>
        </div>

        <script>
            const pinInput = document.getElementById('pinInput');
            const form = document.getElementById('gatewayForm');
            const statusMsg = document.getElementById('statusMsg');

            pinInput.addEventListener('input', function(e) {
                this.value = this.value.replace(/[^0-9]/g, '');

                if (this.value.length > 0) {
                    statusMsg.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin me-2"></i>Verifying Digit ' + this.value.length + '...';
                    statusMsg.style.color = 'var(--primary)';
                } else {
                    statusMsg.innerText = 'Waiting for input...';
                    statusMsg.style.color = '#94a3b8';
                }

                if (this.value.length === 4) {
                    statusMsg.innerHTML = '<i class="fa-solid fa-spinner fa-spin me-2"></i>Authenticating...';
                    this.readOnly = true; 
                    setTimeout(() => form.submit(), 300);
                }
            });
        </script>
    </body>
    </html>
    """
    return render_template_string(html)


@app.route('/auth-<token>', methods=['GET', 'POST'])
def secure_login(token):
    # Verify the token is active
    if 'active_auth_token' not in session or session['active_auth_token'] != token:
        abort(403)

    if request.method == 'POST':
        u, p = request.form['username'].lower().strip(), request.form['password']

        # --- NEW: HARDCODED LOGIN ACCESS ---
        if u == "admin" and p == "admin123":
            session.update({
                'username': 'admin',
                'full_name': 'Default Administrator',
                'user_id': 999,  # Virtual ID
                'user_role': 'super admin',
                'user_department': 'IT'
            })
            session.pop('active_auth_token', None)
            log_audit("admin", "LOGIN_SUCCESS_HARDCODED", "User", 999)
            return redirect(url_for('dashboard'))
        # ------------------------------------

        # Original Database Login Logic continues below...
        with engine.connect() as conn:
            try:
                r = conn.execute(
                    text("SELECT user_id, password_hash, role, email, full_name, department FROM users WHERE username = :u"),
                    {"u": u}).fetchone()

                if r and bcrypt.checkpw(p.encode('utf-8'), r.password_hash.encode('utf-8')):
                    session.update({
                        'username': u,
                        'full_name': r.full_name if r.full_name else u,
                        'user_id': r.user_id,
                        'user_role': r.role,
                        'user_department': r.department if r.department else "General"
                    })
                    session.pop('active_auth_token', None)
                    log_audit(u, "LOGIN_SUCCESS", "User", r.user_id)
                    return redirect(url_for('dashboard'))
            except Exception as e:
                print(f"Login query error: {e}")

        flash("Invalid credentials", "danger")

    return render_template('login.html')


@app.route('/logout')
def logout():
    log_audit(session.get('username'), "LOGOUT", "Session")
    session.clear()
    return redirect(url_for('gateway'))


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user_id = session['user_id']
    if request.method == 'POST':
        if 'signature' not in request.files:
            flash("No file part", "danger")
            return redirect(request.url)
        file = request.files['signature']
        if file.filename == '':
            flash("No selected file", "danger")
            return redirect(request.url)
        if file:
            try:
                signature_data = file.read()
                with engine.begin() as conn:
                    conn.execute(
                        text("UPDATE users SET signature_blob = :sig WHERE user_id = :id"),
                        {"sig": signature_data, "id": user_id}
                    )
                flash("Signature uploaded successfully!", "success")
                log_audit(session['username'], "UPDATE_SIGNATURE", "User", user_id)
            except Exception as e:
                flash(f"Error processing image: {e}", "danger")
        return redirect(url_for('profile'))

    has_signature = False
    with engine.connect() as conn:
        res = conn.execute(text("SELECT signature_blob FROM users WHERE user_id = :id"), {"id": user_id}).scalar()
        if res:
            has_signature = True

    return render_template('profile.html', has_signature=has_signature)


# ==========================================
# 2. TICKETING
# ==========================================
# --- UPDATE DASHBOARD ---
@app.route('/dashboard')
@login_required
def dashboard():
    # 1. SETUP SESSION CONTEXT
    role = session.get('user_role', '').lower()
    user_id = session['user_id']
    username = session['username']
    user_dept = session.get('user_department', 'General')

    # 2. VIEW MODE TOGGLE
    default_view = 'inbox' if role in ['admin', 'super admin', 'manager', 'it support', 'management'] else 'sent'
    view_mode = request.args.get('view', default_view)

    # 3. CAPTURE FILTERS
    page = request.args.get('page', 1, type=int)
    search_q = request.args.get('search', '').strip()
    status_f = request.args.get('status', '')
    assignee_f = request.args.get('assignee', '')
    PER_PAGE = 15

    with engine.connect() as c:
        # Fetch data for modal & filters
        # UPDATE THIS LINE in app.py:
        it_staff_list = c.execute(text("""
                                       SELECT DISTINCT full_name as it_name
                                       FROM users
                                       WHERE full_name IS NOT NULL
                                         AND full_name != '' 
              AND full_name != ' '
                                       ORDER BY full_name ASC
                                       """)).fetchall()
        dept_list = c.execute(text("SELECT name FROM departments ORDER BY name")).fetchall()
        approvers = c.execute(text("SELECT user_id, username FROM users WHERE role IN ('admin', 'manager', 'super admin')")).fetchall()

        # 4. BUILD THE BASE QUERY
        query_str = "SELECT * FROM tickets WHERE 1=1 "
        params = {}

        if view_mode == 'inbox':
            if role in ['admin', 'super admin']:
                pass # Sees everything

            # --- THE HYBRID LOGIC ---
            elif user_dept == 'IT':
                # IT Department EXEMPTION: IT staff see everything sent to 'IT'
                query_str += " AND target_department = 'IT'"

            elif role in ['manager', 'management']:
                # Managers see their whole department queue
                query_str += " AND target_department = :dept"
                params['dept'] = user_dept

            else:
                # ALL OTHER DEPARTMENTS: Strictly per-user (Private Queue)
                query_str += " AND (assigned_it = :u OR assigned_user = :u)"
                params['u'] = username

        else: # view_mode == 'sent'
            query_str += " AND employee_name = :u"
            params['u'] = username

        # 5. APPLY FILTERS
        if search_q:
            query_str += " AND (subject ILIKE :sq OR employee_name ILIKE :sq OR CAST(ticket_id AS TEXT) ILIKE :sq)"
            params['sq'] = f"%{search_q}%"
        if status_f:
            query_str += " AND status = :st"
            params['st'] = status_f
        if assignee_f:
            query_str += " AND (assigned_it = :asg OR assigned_user = :asg)"
            params['asg'] = assignee_f

        # 6. PAGINATION
        total_tickets = c.execute(text(f"SELECT COUNT(*) FROM ({query_str}) as t"), params).scalar() or 0
        paginated_query = text(query_str + " ORDER BY created_at DESC LIMIT :limit OFFSET :offset")
        params.update({"limit": PER_PAGE, "offset": (page - 1) * PER_PAGE})

        tickets_for_page = c.execute(paginated_query, params).fetchall()
        tickets_page_obj = Pagination(page=page, per_page=PER_PAGE, total=total_tickets, items=tickets_for_page)

        approvals = c.execute(text("SELECT * FROM tickets WHERE approver_id = :uid AND status = 'Pending Approval'"), {"uid": user_id}).fetchall()

    return render_template('dashboard.html',
                           tickets_page_obj=tickets_page_obj,
                           approvals=approvals,
                           view_mode=view_mode,
                           search_q=search_q,
                           status_f=status_f,
                           assignee_f=assignee_f,
                           it_staff_list=it_staff_list,
                           departments=dept_list,
                           approvers=approvers)


# --- UPDATE SUBMIT TICKET ---
@app.route('/submit', methods=['GET', 'POST'])
@login_required
def submit_ticket():
    with engine.connect() as c:
        depts = [r[0] for r in c.execute(text("SELECT name FROM departments ORDER BY name")).fetchall()]
        approvers = c.execute(text("SELECT user_id, username FROM users WHERE role IN ('admin', 'manager', 'super admin')")).fetchall()
        ticket_types = ['Incident', 'Request', 'Inquiry', 'Change', 'Problem']

    if request.method == 'POST':
        d = request.form
        target_dept = d.get('target_department')
        assigned_to = d.get('assigned_it')
        ticket_type = d.get('ticket_type')
        support_type = d.get('support_type') # New field from paper form

        ref_file = request.files.get('reference_form')
        ss_file = request.files.get('screenshot_photo')

        ref_blob = ref_file.read() if ref_file and ref_file.filename != '' else None
        ref_name = ref_file.filename if ref_file and ref_file.filename != '' else None
        ss_blob = ss_file.read() if ss_file and ss_file.filename != '' else None
        ss_name = ss_file.filename if ss_file and ss_file.filename != '' else None

        status = "Pending Approval" if ticket_type in ['Request', 'Change'] else "New"

        try:
            with engine.begin() as conn:
                conn.execute(text("""
                    INSERT INTO tickets (
                        employee_name, department, target_department, assigned_it,
                        anydesk_id, email, subject, description, status,
                        ticket_type, support_type, priority, approver_id, created_at,
                        reference_form, reference_form_name, screenshot_photo, screenshot_photo_name
                    )
                    VALUES (
                        :emp, :from_dept, :to_dept, :asg, 
                        :any, :email, :sub, :desc, :stat, 
                        :tt, :st, :prio, :app_id, CURRENT_TIMESTAMP,
                        :ref_b, :ref_n, :ss_b, :ss_n
                    )
                """), {
                    "emp": session['username'],
                    "from_dept": session['user_department'],
                    "to_dept": target_dept,
                    "asg": assigned_to if assigned_to else None,
                    "any": d.get('anydesk_id'),
                    "email": d.get('email'),
                    "sub": d.get('subject'),
                    "desc": d.get('description'),
                    "stat": status,
                    "tt": ticket_type,
                    "st": support_type, # Bind support_type
                    "prio": d.get('priority', 'Medium'),
                    "app_id": d.get('approver_id') if d.get('approver_id') else None,
                    "ref_b": ref_blob, "ref_n": ref_name,
                    "ss_b": ss_blob, "ss_n": ss_name
                })

            flash(f"Ticket successfully sent!", "success")
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f"Error: {e}", "danger")

    return render_template('submit.html', depts=depts, approvers=approvers, ticket_types=ticket_types)


@app.route('/ticket/<int:id>', methods=['GET', 'POST'])
@login_required
def view_ticket(id):
    with engine.connect() as c:
        if request.method == 'POST':
            action = request.form.get('action')
            # Use Full Name if available, otherwise Username
            current_user_identity = session.get('full_name') or session['username']

            with c.begin():
                # 1. LOG: ADDING A COMMENT
                if 'message' in request.form:
                    msg = request.form['message']
                    c.execute(text("INSERT INTO ticket_comments (ticket_id, sender, message) VALUES (:id, :s, :m)"),
                              {"id": id, "s": session['username'], "m": msg})
                    log_audit(session['username'], "ADD_COMMENT", "Ticket", id, details=f"Message: {msg[:50]}...")

                # 2. LOG: HANDLER ACKNOWLEDGING/CLAIMING (TAKING) A TICKET
                elif action == 'take':
                    c.execute(text("""
                                   UPDATE tickets
                                   SET status='In Progress',
                                       assigned_it=:u
                                   WHERE ticket_id = :id
                                     AND status IN ('New', 'Re-Opened', 'Pending Approval')
                                   """), {"u": current_user_identity, "id": id})
                    log_audit(session['username'], "ACKNOWLEDGE_TICKET", "Ticket", id)
                    flash("You have acknowledged this request. Status updated to In Progress.", "info")

                # 3. LOG: HANDLER FULFILLING/RESOLVING A TICKET (Updated for MBPI Work Order)
                elif action == 'resolve':
                    notes = request.form.get('resolution_notes')
                    remarks = request.form.get('it_remarks')
                    priority = request.form.get('priority')
                    target_date = request.form.get('target_date')

                    c.execute(text("""
                                   UPDATE tickets
                                   SET status='Resolved',
                                       resolution_notes=:notes,
                                       it_remarks=:remarks,
                                       priority=:prio,
                                       target_date=:tdate,
                                       resolved_at=CURRENT_TIMESTAMP
                                   WHERE ticket_id = :id
                                   """), {
                        "id": id,
                        "notes": notes,
                        "remarks": remarks,
                        "prio": priority,
                        "tdate": target_date if target_date else None
                    })

                    log_audit(session['username'], "FULFILL_TICKET", "Ticket", id,
                              details=f"Notes: {notes} | Remarks: {remarks}")
                    flash("Request marked as Resolved. Work Order updated.", "success")

                # 4. LOG: REQUESTER CONFIRMING & FINISHING (CLOSING) THE TICKET
                elif action == 'close':
                    t_owner = c.execute(text("SELECT employee_name FROM tickets WHERE ticket_id = :id"),
                                        {"id": id}).scalar()
                    if t_owner in [session['username'], session.get('full_name')]:
                        c.execute(text("UPDATE tickets SET status='Closed' WHERE ticket_id = :id"), {"id": id})
                        c.execute(text("""
                            INSERT INTO ticket_comments (ticket_id, sender, message) 
                            VALUES (:id, 'System', 'Ticket finalized and closed by Requester.')
                        """), {"id": id})
                        log_audit(session['username'], "CONFIRM_CLOSE", "Ticket", id)
                        flash("Ticket has been officially closed. Thank you!", "success")

                # 5. LOG: RE-OPENING A TICKET
                elif action == 'reopen':
                    t_owner = c.execute(text("SELECT employee_name FROM tickets WHERE ticket_id = :id"),
                                        {"id": id}).scalar()
                    if t_owner in [session['username'], session.get('full_name')]:
                        c.execute(text("""
                                       UPDATE tickets
                                       SET status='Re-Opened',
                                           resolved_at=NULL,
                                           resolution_notes=NULL
                                       WHERE ticket_id = :id
                                       """), {"id": id})
                        c.execute(text(
                            "INSERT INTO ticket_comments (ticket_id, sender, message) VALUES (:id, 'System', 'Ticket re-opened by user.')"),
                            {"id": id})
                        log_audit(session['username'], "REOPEN_TICKET", "Ticket", id)
                        flash("Ticket has been re-opened.", "warning")

                # 6. LOG: APPROVALS
                elif action == 'approve':
                    c.execute(text("UPDATE tickets SET status='New', approval_status='Approved' WHERE ticket_id=:id"),
                              {"id": id})
                    log_audit(session['username'], "APPROVE_TICKET", "Ticket", id)

                # 7. LOG: REJECTIONS
                elif action == 'reject':
                    c.execute(
                        text("UPDATE tickets SET status='Rejected', approval_status='Rejected' WHERE ticket_id=:id"),
                        {"id": id})
                    log_audit(session['username'], "REJECT_TICKET", "Ticket", id)

            socketio.emit('ticket_updated', {'type': 'status_change'}, namespace='/')
            # Changed to redirect specifically to the ticket view to refresh data
            return redirect(url_for('view_ticket', id=id))

        # Data Fetching
        tkt = c.execute(text("SELECT * FROM tickets WHERE ticket_id = :id"), {"id": id}).fetchone()
        chats = c.execute(text("SELECT * FROM ticket_comments WHERE ticket_id = :id ORDER BY created_at ASC"),
                          {"id": id}).fetchall()

    return render_template('ticket.html', t=tkt, chats=chats)


@app.route('/print_work_order/<int:id>')
@login_required
def print_work_order(id):
    """Generates the printable digital version of the MBPI Work Order."""
    with engine.connect() as c:
        t = c.execute(text("SELECT * FROM tickets WHERE ticket_id = :id"), {"id": id}).fetchone()

        if not t:
            abort(404)

        # Lookup the User ID of the Assigned IT person to display their signature
        it_sig_id = None
        if t.assigned_it:
            it_sig_id = c.execute(text("""
                SELECT user_id FROM users 
                WHERE full_name = :n OR username = :n
            """), {"n": t.assigned_it}).scalar()

    return render_template('print_work_order.html', t=t, it_sig_id=it_sig_id)


@app.route('/approve_all_pending', methods=['POST'])
@login_required
def approve_all_pending():
    # Security: Check if user is Super Admin
    if session.get('user_role', '').lower() != 'super admin':
        flash("Unauthorized: Only Super Admins can approve all tickets.", "danger")
        return redirect(url_for('dashboard'))

    with engine.connect() as c:
        with c.begin():
            # Find how many are pending (to show in the flash message)
            # CORRECTED: Changed 'Pending' to 'Pending Approval'
            pending_count = c.execute(text("SELECT COUNT(*) FROM tickets WHERE status = 'Pending Approval'")).scalar()

            if pending_count > 0:
                # Update all tickets that are waiting for approval
                # Based on your view_ticket logic: status becomes 'New', approval becomes 'Approved'
                # CORRECTED: Changed 'Pending' to 'Pending Approval'
                c.execute(text("""
                               UPDATE tickets
                               SET status          = 'New',
                                   approval_status = 'Approved'
                               WHERE status = 'Pending Approval'
                               """))

                # Audit Log for the bulk action
                log_audit(session['username'], "APPROVE_ALL_TICKETS", "Ticket", 0,
                          details=f"Approved {pending_count} tickets")

                flash(f"Successfully approved {pending_count} tickets.", "success")

                # Notify the dashboard via SocketIO
                socketio.emit('ticket_updated', {'type': 'bulk_approval'}, namespace='/')
            else:
                flash("No tickets are currently pending approval.", "info")

    return redirect(url_for('dashboard'))


# ==========================================
# 3. KNOWLEDGE BASE & DIRECTORY
# ==========================================
@app.route('/knowledge_base', methods=['GET', 'POST'])
@login_required
def knowledge_base():
    if request.method == 'POST' and session.get('user_role', '').lower() in ['admin', 'super admin']:
        try:
            with engine.begin() as conn:
                conn.execute(text(
                    "INSERT INTO knowledge_base (title, category, content, last_updated_by) VALUES (:t, :c, :cnt, :u)"),
                    {"t": request.form['title'], "c": request.form['category'], "cnt": request.form['content'],
                     "u": session['username']})
            log_audit(session['username'], "CREATE_KB_ARTICLE", "KnowledgeBase", details=request.form['title'])
            flash("Article added successfully.", "success")
        except Exception as e:
            flash(f"Error saving article: {e}", "danger")
        return redirect(url_for('knowledge_base'))

    with engine.connect() as c:
        articles = c.execute(text("SELECT * FROM knowledge_base ORDER BY title")).fetchall()

    return render_template('knowledge_base.html', articles=articles)


@app.route('/directory', methods=['GET', 'POST'])
@login_required
def directory():
    is_admin = session.get('user_role', '').lower() in ['admin', 'super admin']
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search', '').strip()
    PER_PAGE = 12 # Show 12 employees per page

    # Handle POST actions (add, delete, import) same as before...
    # Handle POST actions (add, delete, import)
    if request.method == 'POST' and is_admin:
        action = request.form.get('action')

        if action == 'delete':
            emp_id = request.form.get('id')
            if emp_id:
                with engine.begin() as conn:  # engine.begin() automatically COMMITS the change
                    conn.execute(
                        text("DELETE FROM company_directory WHERE id = :id"),
                        {"id": emp_id}
                    )
                # Important: Redirect after POST to prevent "Resubmit Form" popups
                return redirect(url_for('directory', page=page, search=search_query))

        elif action == 'add':
            # Add your 'add employee' logic here
            name = request.form.get('name')
            dept = request.form.get('dept')
            user = request.form.get('user')
            email = request.form.get('email')
            with engine.begin() as conn:
                conn.execute(
                    text("INSERT INTO company_directory (name, department, username, email) VALUES (:n, :d, :u, :e)"),
                    {"n": name, "d": dept, "u": user, "e": email}
                )
            return redirect(url_for('directory'))
        pass

    with engine.connect() as c:
        # 1. Build the Base Query and Params
        base_q = "FROM company_directory WHERE 1=1"
        params = {}
        if search_query:
            base_q += " AND (name ILIKE :s OR department ILIKE :s OR email ILIKE :s)"
            params['s'] = f"%{search_query}%"

        # 2. Get TOTAL COUNT for this specific search
        total_count = c.execute(text(f"SELECT COUNT(*) {base_q}"), params).scalar() or 0
        total_pages = (total_count + PER_PAGE - 1) // PER_PAGE

        # 3. Get PAGINATED results
        offset = (page - 1) * PER_PAGE
        final_q = text(f"SELECT * {base_q} ORDER BY department, name LIMIT :limit OFFSET :offset")
        params.update({"limit": PER_PAGE, "offset": offset})
        emps = c.execute(final_q, params).fetchall()

        # 4. Fetch departments for the dropdown
        try:
            depts = [r[0] for r in c.execute(text("SELECT name FROM departments ORDER BY name")).fetchall()]
        except:
            depts = []

    # Create a helper object for the template
    pagination = {
        'page': page,
        'pages': total_pages,
        'has_prev': page > 1,
        'has_next': page < total_pages,
        'prev_num': page - 1,
        'next_num': page + 1,
        'total': total_count
    }

    return render_template('directory.html', emps=emps, is_admin=is_admin,
                           search_query=search_query, depts=depts, pagination=pagination)


# ==========================================
# 4. FORMS CENTER
# ==========================================
@app.route('/ier_a', methods=['GET', 'POST'])
@app.route('/ier_a/edit/<int:edit_id>')
@login_required
def ier_a(edit_id=None):
    role = (session.get('user_role') or '').lower()
    user_id = session.get('user_id')
    username = session.get('username')

    with engine.connect() as c:
        # --- POST HANDLING (SAVE NEW) ---
        if request.method == 'POST' and not edit_id:
            d = request.form
            try:
                with engine.begin() as conn:
                    conn.execute(text("""
                                      INSERT INTO ier_forms_a (ier_no, employee_name, position_title, department,
                                                               asset_code, item_description, issue_details,
                                                               dept_head_id, it_personnel_id, created_by, date_reported)
                                      VALUES (:no, :emp, :pos, :dept, :asset, :item, :issue, :dh, :it, :creator,
                                              CURRENT_DATE)
                                      """), {
                                     "no": d.get('ier_no'),
                                     "emp": session.get('full_name'),
                                     "pos": role,
                                     "dept": session.get('user_department'),
                                     "asset": d.get('asset_code'),
                                     "item": d.get('item_description'),
                                     "issue": d.get('issue_details'),
                                     "dh": d.get('dept_head_id'),
                                     "it": d.get('it_personnel_id'),
                                     "creator": username
                                 })
                log_audit(username, "CREATE_IER_A", "FormA", details=f"Ref: {d.get('ier_no')}")
                flash("IER Form A submitted successfully!", "success")
            except Exception as e:
                flash(f"Save Error: {e}", "danger")
            return redirect(url_for('ier_a'))

        # --- DATA FETCHING (WITH PRIVACY FILTER) ---
        # Only Creator, Assigned Manager, IT staff, or Super Admins can view
        query_text = """
                     SELECT f.*,
                            u1.full_name as dept_head_name,
                            u2.full_name as it_staff_name
                     FROM ier_forms_a f
                              LEFT JOIN users u1 ON f.dept_head_id = u1.user_id
                              LEFT JOIN users u2 ON f.it_personnel_id = u2.user_id \
                     """
        params = {"uid": user_id, "uname": username}
        if role != 'super admin':
            query_text += " WHERE f.created_by = :uname OR f.dept_head_id = :uid OR f.it_personnel_id = :uid"

        forms = c.execute(text(query_text + " ORDER BY f.created_at DESC"), params).fetchall()

        all_users = c.execute(text("SELECT user_id, username, full_name FROM users ORDER BY username")).fetchall()
        it_staff = c.execute(
            text("SELECT user_id, full_name FROM users WHERE department = 'IT' ORDER BY full_name")).fetchall()

        edit_data = None
        if edit_id:
            edit_data = c.execute(text("SELECT * FROM ier_forms_a WHERE id = :id"), {"id": edit_id}).fetchone()

    return render_template('ier_a.html', forms=forms, all_users=all_users, it_staff=it_staff, edit_data=edit_data)


@app.route('/approve_ier/<int:id>/<string:role>')
@login_required
def approve_ier(id, role):
    current_uid = session.get('user_id')
    username = session.get('username')

    with engine.begin() as conn:
        form = conn.execute(text("SELECT * FROM ier_forms_a WHERE id = :id"), {"id": id}).fetchone()
        if not form: abort(404)

        if role == 'manager' and current_uid == form.dept_head_id:
            conn.execute(text("UPDATE ier_forms_a SET dept_head_status = 'Approved' WHERE id = :id"), {"id": id})
            log_audit(username, "SIGN_IER_A_MANAGER", "FormA", target_id=id, details=f"Approved {form.ier_no}")
            flash("Manager signature recorded.", "success")

        elif role == 'it' and current_uid == form.it_personnel_id:
            if form.dept_head_status == 'Approved':
                conn.execute(text("""
                                  UPDATE ier_forms_a
                                  SET it_status       = 'Approved',
                                      workflow_status = 'Completed'
                                  WHERE id = :id
                                  """), {"id": id})
                log_audit(username, "SIGN_IER_A_IT", "FormA", target_id=id, details=f"Verified {form.ier_no}")
                flash("IT verification complete. Record Closed.", "success")
            else:
                flash("Manager signature required first.", "warning")

    return redirect(url_for('ier_a'))


@app.route('/edit_ier_a/<int:id>', methods=['POST'])
@login_required
def edit_ier_a(id):
    # Security Check: Only Super Admin can edit
    if session.get('user_role', '').lower() != 'super admin':
        flash("Access Denied: Only Super Admins can edit records.", "danger")
        return redirect(url_for('ier_a'))

    d = request.form
    try:
        with engine.begin() as conn:
            conn.execute(text("""
                              UPDATE ier_forms_a
                              SET ier_no           = :no,
                                  position_title   = :pos,
                                  department       = :dep,
                                  asset_code       = :asset,
                                  item_description = :item,
                                  issue_details    = :iss,
                                  dept_head_id     = :dh_id,
                                  it_personnel_id  = :it_id
                              WHERE id = :id
                              """), {
                             "no": d.get('ier_no'), "pos": d.get('position_title'),
                             "dep": d.get('department'), "asset": d.get('asset_code'),
                             "item": d.get('item_description'), "iss": d.get('issue_details'),
                             "dh_id": d.get('dept_head_id'), "it_id": d.get('it_personnel_id'),
                             "id": id
                         })
        flash(f"Record {d.get('ier_no')} updated successfully.", "success")
        log_audit(session['username'], "EDIT_IER_A", "Form", target_id=id)
    except Exception as e:
        flash(f"Update Error: {e}", "danger")

    return redirect(url_for('ier_a'))


@app.route('/ier_b', methods=['GET', 'POST'])
@login_required
def ier_b():
    role = (session.get('user_role') or '').lower()
    user_id = session.get('user_id')
    username = session.get('username')

    with engine.connect() as c:
        if request.method == 'POST':
            d = request.form
            items, qtys, refs, amts = d.getlist('mat_item[]'), d.getlist('mat_qty[]'), d.getlist('mat_ref[]'), d.getlist('mat_amount[]')
            mats_list = [{'item': items[i], 'qty': qtys[i], 'ref': refs[i], 'amount': amts[i]} for i in range(len(items)) if items[i].strip()]

            try:
                with engine.begin() as conn:
                    conn.execute(text("""
                        INSERT INTO ier_forms_b (
                            ier_no, ref_ier_a_no, employee_name, date_reported, position_title,
                            item_description, department, endorsee, asset_code, cause_issue,
                            prepared_by_id, noted_by_id, received_by_id, materials, created_at
                        ) VALUES (
                            :no, :ref, :emp, :dr, :pos, :item, :dep, :end, :code, :cause,
                            :prep, :note, :recv, :mats, CURRENT_TIMESTAMP
                        )
                    """), {
                        "no": d.get('ier_no'), "ref": d.get('ref_ier_a_no'), "emp": d.get('employee_name'),
                        "dr": d.get('date_reported'), "pos": d.get('position_title'), "item": d.get('item_description'),
                        "dep": d.get('department'), "end": d.get('endorsee'), "code": d.get('asset_code'),
                        "cause": d.get('cause_issue'), "prep": d.get('prepared_by_id'), "note": d.get('noted_by_id'),
                        "recv": d.get('received_by_id'), "mats": json.dumps(mats_list)
                    })
                log_audit(username, "CREATE_IER_B", "FormB", details=f"Ref: {d.get('ier_no')}")
                flash("Technical Investigation Saved.", "success")
            except Exception as e:
                flash(f"Error: {e}", "danger")
            return redirect(url_for('ier_b'))

        # Fetch with Privacy Filter
        query_text = """
            SELECT f.*, u1.full_name as prep_name, u2.full_name as note_name, u3.username as recv_name
            FROM ier_forms_b f
            LEFT JOIN users u1 ON f.prepared_by_id = u1.user_id
            LEFT JOIN users u2 ON f.noted_by_id = u2.user_id
            LEFT JOIN users u3 ON f.received_by_id = u3.user_id
        """
        params = {"uid": user_id}
        if role != 'super admin':
            query_text += " WHERE f.prepared_by_id = :uid OR f.noted_by_id = :uid OR f.received_by_id = :uid"

        forms = c.execute(text(query_text + " ORDER BY f.created_at DESC"), params).fetchall()
        it_staff = c.execute(text("SELECT user_id, full_name FROM users WHERE department = 'IT'")).fetchall()
        all_users = c.execute(text("SELECT user_id, username, full_name FROM users ORDER BY username")).fetchall()

    return render_template('ier_b.html', forms=forms, it_staff=it_staff, all_users=all_users)


@app.route('/print/ier_a/<int:id>')
@login_required
def print_ier_a(id):
    role = (session.get('user_role') or '').lower()
    user_id = session.get('user_id')
    username = session.get('username')

    with engine.connect() as c:
        query = text("""
            SELECT f.*, 
                   u1.full_name as prep_name, u1.user_id as prep_uid, u1.signature_blob as prep_sig,
                   u2.full_name as dept_head_name, u2.user_id as dept_uid, u2.signature_blob as dept_sig,
                   u3.full_name as it_personnel_name, u3.user_id as it_uid, u3.signature_blob as it_sig
            FROM ier_forms_a f
            LEFT JOIN users u1 ON f.created_by = u1.username
            LEFT JOIN users u2 ON f.dept_head_id = u2.user_id
            LEFT JOIN users u3 ON f.it_personnel_id = u3.user_id
            WHERE f.id = :id
        """)
        f = c.execute(query, {"id": id}).fetchone()

    if not f: abort(404)

    # Security: Only involved parties see the print view
    if role != 'super admin':
        if username != f.created_by and user_id != f.dept_head_id and user_id != f.it_personnel_id:
            abort(403)

    return render_template('print_ier_a.html', f=f)


@app.route('/print/ier_b/<int:id>')
@login_required
def print_ier_b(id):
    with engine.connect() as c:
        query = text("""
                     SELECT f.*,
                            u1.full_name      as prep_name,
                            u1.signature_blob as prep_sig,
                            u1.user_id        as prep_uid,
                            u2.full_name      as noted_name,
                            u2.signature_blob as noted_sig,
                            u2.user_id        as noted_uid,
                            u3.full_name      as recv_name,
                            u3.signature_blob as recv_sig,
                            u3.user_id        as recv_uid
                     FROM ier_forms_b f
                              LEFT JOIN users u1 ON f.prepared_by_id = u1.user_id
                              LEFT JOIN users u2 ON f.noted_by_id = u2.user_id
                              LEFT JOIN users u3 ON f.received_by_id = u3.user_id
                     WHERE f.id = :id
                     """)
        form = c.execute(query, {"id": id}).fetchone()

    if not form: abort(404)
    return render_template('print_ier_b.html', f=form)

@app.route('/edit_ier_b/<int:id>', methods=['POST'])
@login_required
def edit_ier_b(id):
    if session.get('user_role', '').lower() != 'super admin':
        flash("Access Denied", "danger")
        return redirect(url_for('ier_b'))

    d = request.form
    # Process dynamic materials from the edit form
    items, qtys, refs, amts = d.getlist('mat_item[]'), d.getlist('mat_qty[]'), d.getlist('mat_ref[]'), d.getlist('mat_amount[]')
    mats_list = [{'item': items[i], 'qty': qtys[i], 'ref': refs[i], 'amount': amts[i]} for i in range(len(items)) if items[i].strip()]

    try:
        with engine.begin() as conn:
            conn.execute(text("""
                UPDATE ier_forms_b SET 
                ier_no=:no, employee_name=:emp, date_reported=:dr, position_title=:pos, 
                item_description=:item, department=:dep, endorsee=:end, asset_code=:code, 
                cause_issue=:cause, recommendations=:rec, prepared_by_id=:prep, 
                noted_by_id=:note, received_by_id=:recv, actions_taken=:act, 
                conducted_by=:cond, date_started=:ds, time_started=:ts, 
                date_completed=:dc, time_completed=:tc, materials=:mat, results=:res
                WHERE id = :id
            """), {
                "no": d.get('ier_no'), "emp": d.get('employee_name'), "dr": d.get('date_reported'),
                "pos": d.get('position_title'), "item": d.get('item_description'), "dep": d.get('department'),
                "end": d.get('endorsee'), "code": d.get('asset_code'), "cause": d.get('cause_issue'),
                "rec": d.get('recommendations'), "prep": d.get('prepared_by_id'), "note": d.get('noted_by_id'),
                "recv": d.get('received_by_id'), "act": d.get('actions_taken'), "cond": d.get('conducted_by'),
                "ds": d.get('date_started'), "ts": d.get('time_started'), "dc": d.get('date_completed'),
                "tc": d.get('time_completed'), "mat": json.dumps(mats_list), "res": d.get('results'), "id": id
            })
        flash("Technical Report updated successfully.", "success")
    except Exception as e:
        flash(f"Update Error: {e}", "danger")
    return redirect(url_for('ier_b'))


@app.route('/approve_ier_b/<int:id>/<string:role>')
@login_required
def approve_ier_b(id, role):
    user_role = (session.get('user_role') or '').lower()
    uid = session.get('user_id')

    with engine.begin() as conn:
        form = conn.execute(text("SELECT * FROM ier_forms_b WHERE id = :id"), {"id": id}).fetchone()
        if not form: abort(404)

        if role == 'it_lead' and uid == form.noted_by_id:
            conn.execute(text("UPDATE ier_forms_b SET it_lead_status = 'Approved' WHERE id = :id"), {"id": id})
            log_audit(session['username'], "VERIFY_IER_B_LEAD", "FormB", target_id=id)
            flash("IT Lead verification recorded.", "success")

        elif role == 'asset':
            if user_role in ['asset manager', 'admin', 'super admin',
                             'management'] and form.it_lead_status == 'Approved':
                conn.execute(text(
                    "UPDATE ier_forms_b SET asset_status = 'Approved', workflow_status = 'Completed' WHERE id = :id"),
                             {"id": id})
                log_audit(session['username'], "FINAL_APPROVE_IER_B", "FormB", target_id=id)
                flash("Final Asset Approval Complete.", "success")
            else:
                flash("Prerequisites not met for Asset Approval.", "warning")

    return redirect(url_for('ier_b'))

# ==========================================
# ASSET DEPARTMENT: IER CENTRAL HUB
# ==========================================
@app.route('/ier_hub')
@login_required
def ier_hub():
    # This route provides a unified view of ALL IER records
    # for the Asset and Audit roles.
    with engine.connect() as c:
        try:
            # Fetch all IER Form A (User Requests)
            forms_a = c.execute(text("SELECT * FROM ier_forms_a ORDER BY created_at DESC")).fetchall()
            # Fetch all IER Form B (IT Technical Reports)
            forms_b = c.execute(text("SELECT * FROM ier_forms_b ORDER BY created_at DESC")).fetchall()
        except Exception as e:
            flash(f"Database Error accessing IER records: {e}", "danger")
            return redirect(url_for('dashboard'))

    return render_template('ier_hub.html', forms_a=forms_a, forms_b=forms_b)

# ==========================================
# 5. MANAGEMENT & ANALYTICS
# ==========================================
@app.route('/analytics')
@admin_required  # Or manager_or_management_required if you want managers to see this
def analytics():
    # 1. SET THE HARD CUT-OFF DATE
    START_DATE = datetime(2026, 3, 23)
    NOW = datetime.now()

    # 2. GET PERMISSIONS & FILTERS
    role = session.get('user_role', '').lower()
    user_dept = session.get('user_department')

    # If Admin, allow "All" or a specific dept. If Manager, force their department.
    if role in ['super admin', 'admin']:
        selected_dept = request.args.get('dept', 'All')
    else:
        selected_dept = user_dept

    with engine.connect() as c:
        try:
            # Fetch department list for the dropdown filter
            depts_list = [r[0] for r in c.execute(text("SELECT name FROM departments ORDER BY name")).fetchall()]

            # 3. BUILD BASE FILTER
            # We filter by 'target_department' because analytics usually measures
            # the performance of the department HANDLING the tickets.
            base_sql = "WHERE created_at >= :sd"
            params = {"sd": START_DATE}

            if selected_dept != 'All':
                base_sql += " AND target_department = :td"
                params["td"] = selected_dept

            # --- TOP LEVEL STATS ---
            total_tickets = c.execute(text(f"SELECT COUNT(*) FROM tickets {base_sql}"), params).scalar() or 0

            resolved_count = c.execute(
                text(f"SELECT COUNT(*) FROM tickets {base_sql} AND status = 'Resolved'"),
                params).scalar() or 0

            open_count = c.execute(
                text(f"SELECT COUNT(*) FROM tickets {base_sql} AND status NOT IN ('Resolved', 'Rejected')"),
                params).scalar() or 0

            # SLA Breaches
            sla_breaches = c.execute(text(f"""
                SELECT COUNT(*) FROM tickets 
                {base_sql}
                AND (
                    (status = 'Resolved' AND resolved_at > resolution_due) OR
                    (status NOT IN ('Resolved', 'Rejected') AND CURRENT_TIMESTAMP > resolution_due)
                )
            """), params).scalar() or 0

            # --- 7-DAY TREND LOGIC ---
            trend_labels = []
            trend_data = []
            db_counts = c.execute(text(f"""
                SELECT DATE(created_at) as day, COUNT(*)
                FROM tickets
                {base_sql} AND created_at >= CURRENT_DATE - INTERVAL '6 days'
                GROUP BY day
            """), params).fetchall()

            counts_dict = {row[0]: row[1] for row in db_counts}
            for i in range(6, -1, -1):
                target_day = (NOW - timedelta(days=i)).date()
                trend_labels.append(target_day.strftime('%a'))
                if target_day < START_DATE.date():
                    trend_data.append(0)
                else:
                    trend_data.append(counts_dict.get(target_day, 0))

            # --- STATUS BREAKDOWN (Donut) ---
            pending = c.execute(
                text(f"SELECT COUNT(*) FROM tickets {base_sql} AND status = 'Pending Approval'"),
                params).scalar() or 0

            overdue = c.execute(text(f"""
                SELECT COUNT(*) FROM tickets 
                {base_sql} AND status NOT IN ('Resolved', 'Rejected') 
                AND resolution_due < CURRENT_TIMESTAMP
            """), params).scalar() or 0

            # Values: [Resolved, Open(Active), Pending, Overdue]
            status_values = [resolved_count, (open_count - pending - overdue), pending, overdue]

            # --- DYNAMIC DISTRIBUTION CHART ---
            if selected_dept == 'All':
                # Show which departments are receiving the most tickets
                dist_title = "Top Target Departments"
                dist_res = c.execute(text(f"""
                    SELECT target_department, COUNT(*) as c
                    FROM tickets {base_sql}
                    GROUP BY target_department ORDER BY c DESC LIMIT 5
                """), params).fetchall()
            else:
                # Show which categories are most common within the selected department
                dist_title = f"Top Categories in {selected_dept}"
                dist_res = c.execute(text(f"""
                    SELECT category, COUNT(*) as c
                    FROM tickets {base_sql}
                    GROUP BY category ORDER BY c DESC LIMIT 5
                """), params).fetchall()

            dist_labels = [r[0] if r[0] else "Uncategorized" for r in dist_res]
            dist_data = [r[1] for r in dist_res]

        except Exception as e:
            print(f"Analytics Error: {e}")
            flash("Error loading analytics data.", "danger")
            return redirect(url_for('dashboard'))

    return render_template('analytics.html',
                           total_tickets=total_tickets,
                           open_tickets=open_count,
                           resolved_tickets=resolved_count,
                           sla_breaches=sla_breaches,
                           trend_labels=trend_labels,
                           trend_data=trend_data,
                           status_data=status_values,
                           dist_labels=dist_labels,
                           dist_data=dist_data,
                           dist_title=dist_title,
                           selected_dept=selected_dept,
                           depts_list=depts_list)

import json


@app.route('/sla_analytics')
@login_required  # Changed to login_required to allow Managers/Staff to see their own data
def sla_analytics():
    # 1. SETUP FILTERS & PERMISSIONS
    START_DATE = datetime(2026, 3, 23)
    NOW = datetime.now()
    role = session.get('user_role', '').lower()
    user_dept = session.get('user_department', 'General')

    # Capture department filter from URL
    # If Admin/Super Admin, default to 'All'. If Manager/Staff, default to their own dept.
    default_dept = 'All' if role in ['admin', 'super admin'] else user_dept
    selected_dept = request.args.get('dept', default_dept)

    with engine.connect() as c:
        # 2. FETCH DEPARTMENT LIST (For the dropdown)
        depts_list = [r[0] for r in c.execute(text("SELECT name FROM departments ORDER BY name")).fetchall()]

        # 3. BUILD BASE FILTER SQL
        base_sql = " WHERE created_at >= :sd"
        params = {"sd": START_DATE}

        if selected_dept != 'All':
            base_sql += " AND target_department = :td"
            params['td'] = selected_dept

        # --- TOP STATS ---
        # Total Tickets in scope
        total_tickets = c.execute(text(f"SELECT COUNT(*) FROM tickets {base_sql}"), params).scalar() or 0

        # Tickets resolved within SLA
        sla_met = c.execute(text(f"""
            SELECT COUNT(*) FROM tickets 
            {base_sql} AND status = 'Resolved' AND resolved_at <= resolution_due
        """), params).scalar() or 0

        # Total Resolved tickets (for compliance %)
        total_resolved = c.execute(text(f"SELECT COUNT(*) FROM tickets {base_sql} AND status = 'Resolved'"),
                                   params).scalar() or 0
        overall_compliance = round((sla_met / total_resolved * 100), 1) if total_resolved > 0 else 0

        # Average Resolution Time (in hours)
        avg_res_raw = c.execute(text(f"""
            SELECT AVG(EXTRACT(EPOCH FROM (resolved_at - created_at)) / 3600) 
            FROM tickets {base_sql} AND status = 'Resolved'
        """), params).scalar() or 0

        # --- 30-DAY TREND (SAT/SUN FILLER) ---
        trend_labels = []
        trend_values = []
        db_trend = c.execute(text(f"""
            SELECT DATE(created_at) as day, COUNT(*)
            FROM tickets
            {base_sql} AND created_at >= CURRENT_DATE - INTERVAL '29 days'
            GROUP BY day
        """), params).fetchall()

        counts_dict = {row[0]: row[1] for row in db_trend}
        for i in range(29, -1, -1):
            d = (NOW - timedelta(days=i)).date()
            trend_labels.append(d.strftime('%b %d'))
            trend_values.append(counts_dict.get(d, 0))

        # --- STATUS BREAKDOWN (For Doughnut) ---
        s_counts = c.execute(text(f"""
            SELECT 
                COUNT(CASE WHEN status NOT IN ('Resolved', 'Rejected') THEN 1 END) as open,
                COUNT(CASE WHEN status = 'Resolved' THEN 1 END) as res,
                COUNT(CASE WHEN status = 'Pending Approval' THEN 1 END) as pen
            FROM tickets {base_sql}
        """), params).fetchone()

        # --- STAFF PERFORMANCE (Met vs Missed) ---
        # Note: 'assigned_it' acts as the 'Handler' for whichever dept is selected
        staff_perf = c.execute(text(f"""
            SELECT assigned_it,
                   COUNT(CASE WHEN resolved_at <= resolution_due THEN 1 END) as met,
                   COUNT(CASE WHEN resolved_at > resolution_due THEN 1 END)  as missed
            FROM tickets
            {base_sql} AND status = 'Resolved' AND assigned_it IS NOT NULL
            GROUP BY assigned_it LIMIT 5
        """), params).fetchall()

        # --- PRIORITY PERFORMANCE ---
        prio_perf = c.execute(text(f"""
            SELECT priority,
                   ROUND(COUNT(CASE WHEN resolved_at <= resolution_due THEN 1 END) * 100.0 /
                         NULLIF(COUNT(*), 0), 1) as met_pct
            FROM tickets
            {base_sql} AND status = 'Resolved'
            GROUP BY priority
        """), params).fetchall()

        # Overdue Tickets List (Specific to selection)
        overdue_tickets = c.execute(text(f"""
            SELECT ticket_id, subject, employee_name, assigned_it, resolution_due
            FROM tickets
            {base_sql} AND status NOT IN ('Resolved', 'Rejected')
            AND resolution_due < CURRENT_TIMESTAMP
            ORDER BY resolution_due ASC
        """), params).fetchall()

        # --- BUILD FINAL PAYLOAD ---
        chart_data = {
            "trend_labels": trend_labels,
            "trend_values": trend_values,
            "status_data": [s_counts.open or 0, s_counts.res or 0, s_counts.pen or 0],
            "staff_labels": [r.assigned_it for r in staff_perf],
            "staff_met_data": [int(r.met) for r in staff_perf],
            "staff_missed_data": [int(r.missed) for r in staff_perf],
            "priority_labels": [str(r.priority) for r in prio_perf],
            "priority_met_data": [float(r.met_pct or 0) for r in prio_perf]
        }

    return render_template('sla_analytics.html',
                           total_tickets=total_tickets,
                           overall_compliance=overall_compliance,
                           avg_res_hours=round(avg_res_raw, 1),
                           overdue_tickets=overdue_tickets,
                           overdue_count=len(overdue_tickets),
                           selected_dept=selected_dept,
                           depts_list=depts_list,
                           payload=json.dumps(chart_data))

@app.route('/export_report')
@admin_required
def export_report():
    with engine.connect() as c:
        res = c.execute(text(
            "SELECT ticket_id, employee_name, department, subject, status, priority, created_at FROM tickets")).fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Employee', 'Dept', 'Subject', 'Status', 'Priority', 'Date'])
    for r in res: writer.writerow(list(r))
    output.seek(0)
    log_audit(session['username'], "EXPORT_REPORT", "System")
    return send_file(io.BytesIO(output.getvalue().encode('utf-8')), mimetype='text/csv', as_attachment=True,
                     download_name="Helpdesk_Report.csv")


@app.route('/assets/user/<username>')
@admin_required
def user_assets(username):
    with engine.connect() as c:
        asts = c.execute(text("SELECT * FROM assets WHERE assigned_user ILIKE :user ORDER BY asset_id"),
                         {"user": username}).fetchall()
    return render_template('generic_list.html',
                           rows=asts,
                           headers=['Asset ID', 'Asset Tag', 'Asset Type', 'Assigned User', 'Notes', 'Created At'],
                           title=f"Assets Assigned to {username}")


@app.route('/assets', methods=['GET', 'POST'])
@login_required
def assets():
    role = session.get('user_role', '').lower()
    user_dept = session.get('user_department')  # Ensure this is set at login

    if request.method == 'POST':
        # Only Admins and Asset Managers can add/edit
        if role not in ['admin', 'super admin', 'asset manager']:
            flash("Access Denied.", "danger")
            return redirect(url_for('assets'))

        action = request.form.get('action')
        try:
            with engine.begin() as c:
                if action == 'add':
                    c.execute(text("""
                                   INSERT INTO assets (asset_tag, asset_type, assigned_user, department, notes)
                                   VALUES (:tag, :type, :user, :dept, :notes)"""),
                              {"tag": request.form['tag'], "type": request.form['type'],
                               "user": request.form['user'], "dept": request.form['department'],
                               "notes": request.form['notes']})
                elif action == 'delete':
                    c.execute(text("DELETE FROM assets WHERE asset_id=:id"), {"id": request.form['id']})
        except Exception as e:
            flash(f"Database Error: {e}", "danger")
        return redirect(url_for('assets'))

    # --- THE SILOED FETCH LOGIC ---
    with engine.connect() as c:
        query = "SELECT * FROM assets WHERE 1=1"
        params = {}

        # Security: If not a Super Admin, only show assets in their department
        if role != 'super admin':
            query += " AND department = :d"
            params['d'] = user_dept

        asts = c.execute(text(query + " ORDER BY asset_id DESC"), params).fetchall()

        # Fetch departments for the "Add Asset" dropdown
        depts = [r[0] for r in c.execute(text("SELECT name FROM departments ORDER BY name")).fetchall()]

    return render_template('assets.html', asts=asts, depts=depts)


@app.route('/users', methods=['GET', 'POST'])
@admin_required
def users():
    if request.method == 'POST':
        action = request.form.get('action')
        try:
            with engine.begin() as c:
                if action == 'add':
                    hp = bcrypt.hashpw(request.form['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                    c.execute(text("""
                        INSERT INTO users (username, full_name, email, password_hash, role, department) 
                        VALUES (:u, :fn, :e, :p, :r, :d)"""),
                              {
                                  "u": request.form['username'], "fn": request.form.get('full_name', ''),
                                  "e": request.form.get('email', ''), "p": hp,
                                  "r": request.form['role'], "d": request.form.get('department')
                              })
                    log_audit(session['username'], "CREATE_USER", "User", details=request.form['username'])
                    flash("User created successfully.", "success")

                elif action == 'edit':
                    uid = request.form.get('id')
                    c.execute(text("""
                        UPDATE users SET username=:u, full_name=:fn, email=:e, role=:r, department=:d 
                        WHERE user_id=:id"""),
                              {
                                  "u": request.form.get('username'), "fn": request.form.get('full_name', ''),
                                  "e": request.form.get('email', ''), "r": request.form.get('role'),
                                  "d": request.form.get('department'), "id": uid
                              })
                    new_pass = request.form.get('password')
                    if new_pass and new_pass.strip() != "":
                        hp = bcrypt.hashpw(new_pass.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                        c.execute(text("UPDATE users SET password_hash=:p WHERE user_id=:id"), {"p": hp, "id": uid})
                    log_audit(session['username'], "MODIFY_USER", "User", target_id=uid)
                    flash("User updated successfully.", "success")

                elif action == 'delete' and int(request.form['id']) != session['user_id']:
                    c.execute(text("DELETE FROM users WHERE user_id=:id"), {"id": request.form['id']})
                    flash("User deleted.", "success")

        except Exception as e:
            flash(f"Database Error: {e}", "danger")
        return redirect(url_for('users'))

    # --- This GET request part is what needed fixing ---
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search', '').strip()
    PER_PAGE = 10

    with engine.connect() as c:
        # THIS IS THE CRITICAL FIX: Fetch departments for the dropdowns
        try:
            depts = [r[0] for r in c.execute(text("SELECT name FROM departments ORDER BY name")).fetchall()]
        except Exception:
            depts = [] # Fallback if departments table doesn't exist

        where_clause = " WHERE 1=1 "
        params = {}
        if search_query:
            where_clause += " AND (username ILIKE :s OR full_name ILIKE :s OR email ILIKE :s OR role ILIKE :s OR department ILIKE :s) "
            params['s'] = f"%{search_query}%"

        total_count = c.execute(text(f"SELECT COUNT(*) FROM users {where_clause}"), params).scalar() or 0

        offset = (page - 1) * PER_PAGE
        params.update({"limit": PER_PAGE, "offset": offset})

        sql = text(f"""
            SELECT user_id, username, full_name, email, role, department 
            FROM users {where_clause} 
            ORDER BY user_id LIMIT :limit OFFSET :offset
        """)
        items = c.execute(sql, params).fetchall()

        pagination = Pagination(page=page, per_page=PER_PAGE, total=total_count, items=items)

    # THIS IS THE CRITICAL FIX: Pass 'depts' to the template
    return render_template('users.html', user_list=items, pagination=pagination, search_query=search_query, depts=depts)


@app.route('/bulk_assign_dept', methods=['POST'])
@admin_required
def bulk_assign_dept():
    dept = request.form.get('target_department')
    user_ids = request.form.getlist('user_ids')  # Gets all selected checkboxes

    if not dept or not user_ids:
        flash("Please select at least one user and a target department.", "warning")
        return redirect(url_for('users'))

    try:
        with engine.begin() as conn:
            # Use a safe query to update multiple users at once
            conn.execute(text("UPDATE users SET department = :d WHERE user_id = ANY(:ids)"),
                         {"d": dept, "ids": [int(i) for i in user_ids]})

        log_audit(session['username'], "BULK_ASSIGN_DEPARTMENT", "User",
                  details=f"Moved {len(user_ids)} users to {dept}")
        flash(f"Successfully moved {len(user_ids)} users to the '{dept}' department.", "success")
    except Exception as e:
        flash(f"An error occurred during bulk assignment: {e}", "danger")

    return redirect(url_for('users'))

@app.route('/it_staff', methods=['GET', 'POST'])
@admin_required
def it_staff():
    if request.method == 'POST':
        action = request.form.get('action')
        try:
            with engine.begin() as c:
                if action == 'add':
                    c.execute(text("INSERT INTO preferred_it_list (it_name) VALUES (:n)"), {"n": request.form['name']})
                    log_audit(session['username'], "ADD_IT_STAFF", "ITStaff", details=request.form['name'])
                elif action == 'delete':
                    c.execute(text("DELETE FROM preferred_it_list WHERE id=:id"), {"id": request.form['id']})
                    log_audit(session['username'], "DELETE_IT_STAFF", "ITStaff", target_id=request.form['id'])
        except Exception as e:
            flash(f"Database Error: {e}", "danger")
        return redirect(url_for('it_staff'))

    with engine.connect() as c:
        staff = c.execute(text("SELECT * FROM preferred_it_list ORDER BY it_name")).fetchall()
    return render_template('it_staff.html', staff=staff)


@app.route('/departments', methods=['GET', 'POST'])
@admin_required
def departments():
    if request.method == 'POST':
        action = request.form.get('action')

        try:
            with engine.begin() as conn:
                if action == 'add':
                    # Only get the name from the form
                    dept_name = request.form.get('name', '').strip()

                    if dept_name:
                        # SQL: Strictly insert ONLY into the 'name' column
                        conn.execute(
                            text("INSERT INTO departments (name) VALUES (:n) ON CONFLICT (name) DO NOTHING"),
                            {"n": dept_name}
                        )
                        log_audit(session.get('username'), "ADD_DEPARTMENT", "Department", details=dept_name)
                        flash(f"Department '{dept_name}' registered successfully!", "success")
                    else:
                        flash("Department name is required.", "warning")

                elif action == 'delete':
                    dept_id = request.form.get('id')
                    # Note: This might fail if employees are still linked to this department
                    conn.execute(text("DELETE FROM departments WHERE id = :id"), {"id": dept_id})
                    log_audit(session.get('username'), "DELETE_DEPARTMENT", "Department", target_id=dept_id)
                    flash("Department removed.", "info")

        except Exception as e:
            # Catching foreign key errors (if employees are assigned to this dept)
            if "foreign key" in str(e).lower():
                flash("Error: Cannot delete department. There are employees still assigned to it.", "danger")
            else:
                flash(f"Database Error: {e}", "danger")

        return redirect(url_for('departments'))

    # GET logic: Fetch list for display
    with engine.connect() as conn:
        try:
            # We only fetch ID and Name
            depts = conn.execute(text("SELECT id, name FROM departments ORDER BY name")).fetchall()
        except:
            depts = []

    return render_template('departments.html', depts=depts)


@app.route('/slas', methods=['GET', 'POST'])
@admin_required
def slas():
    if request.method == 'POST':
        action = request.form.get('action')
        try:
            with engine.begin() as c:
                if action == 'save':
                    c.execute(text("""
                                   INSERT INTO sla_policies (ticket_type, priority, resolve_in_hours)
                                   VALUES (:tt, :p, :h) ON CONFLICT (ticket_type, priority) 
                        DO
                                   UPDATE SET resolve_in_hours = EXCLUDED.resolve_in_hours
                                   """), {
                                  "tt": request.form['ticket_type'],
                                  "p": request.form['priority'],
                                  "h": int(request.form['hours'])
                              })
                    log_audit(session['username'], "SAVE_SLA", "System",
                              details=f"{request.form['ticket_type']} - {request.form['priority']}")
                    flash("SLA Policy saved successfully.", "success")

                elif action == 'delete':
                    c.execute(text("DELETE FROM sla_policies WHERE id=:id"), {"id": request.form['id']})
                    log_audit(session['username'], "DELETE_SLA", "System", target_id=request.form['id'])
                    flash("SLA Policy deleted.", "success")
        except Exception as e:
            flash(f"Database Error: {e}", "danger")
        return redirect(url_for('slas'))

    with engine.connect() as c:
        try:
            policies = c.execute(text("SELECT * FROM sla_policies ORDER BY ticket_type, resolve_in_hours")).fetchall()
        except Exception:
            policies = []
    return render_template('slas.html', policies=policies)


@app.route('/manage_departments', methods=['GET', 'POST'])
@login_required
@admin_required  # Only Admins can manage the company structure
def manage_departments():
    if request.method == 'POST':
        action = request.form.get('action')
        dept_name = request.form.get('name', '').strip()
        dept_head = request.form.get('dept_head', '').strip()

        try:
            with engine.begin() as conn:
                if action == 'add' and dept_name:
                    conn.execute(text("""
                                      INSERT INTO departments (name, dept_head)
                                      VALUES (:n, :h) ON CONFLICT (name) DO NOTHING
                                      """), {"n": dept_name, "h": dept_head})
                    log_audit(session['username'], "ADD_DEPARTMENT", "System", details=dept_name)
                    flash(f"Department '{dept_name}' added successfully.", "success")

                elif action == 'delete':
                    dept_id = request.form.get('id')
                    # Get name before deleting for the log
                    name = conn.execute(text("SELECT name FROM departments WHERE id = :id"), {"id": dept_id}).scalar()
                    conn.execute(text("DELETE FROM departments WHERE id = :id"), {"id": dept_id})
                    log_audit(session['username'], "DELETE_DEPARTMENT", "System", details=name)
                    flash("Department removed.", "warning")
        except Exception as e:
            flash(f"Error: {e}", "danger")
        return redirect(url_for('manage_departments'))

    # GET Request: Fetch all departments
    with engine.connect() as conn:
        depts = conn.execute(text("SELECT * FROM departments ORDER BY name")).fetchall()
        # Also fetch users to populate the "Department Head" dropdown
        users = conn.execute(text("SELECT full_name, username FROM users ORDER BY full_name")).fetchall()

    return render_template('manage_departments.html', depts=depts, users=users)


# ==========================================
# 6. SYSTEM
# ==========================================
@app.route('/archive', methods=['GET', 'POST'])
@admin_required
def archive():
    if request.method == 'POST' and archive_engine:
        action = request.form.get('action')
        try:
            with engine.begin() as live_conn, archive_engine.begin() as arch_conn:
                if action == 'backup_tickets':
                    # 1. Fetch resolved tickets
                    res = live_conn.execute(text("SELECT * FROM tickets WHERE status='Resolved'")).fetchall()
                    count = 0
                    for r in res:
                        # 2. Insert into archive
                        arch_conn.execute(text("""
                                               INSERT INTO archived_tickets (ticket_id, employee_name, subject, status, archived_at)
                                               VALUES (:id, :emp, :sub, :stat,
                                                       CURRENT_TIMESTAMP) ON CONFLICT (ticket_id) DO NOTHING
                                               """), {"id": r.ticket_id, "emp": r.employee_name, "sub": r.subject,
                                                      "stat": r.status})
                        count += 1
                    log_audit(session['username'], "BACKUP_TICKETS", "Archive", details=f"Archived {count} tickets")
                    flash(f"Successfully archived {count} resolved tickets to local backup.", "success")

                elif action == 'backup_iers':
                    # Similar logic would apply for IER forms
                    log_audit(session['username'], "BACKUP_IER_FORMS", "Archive")
                    flash("IER Backup process completed.", "success")
        except Exception as e:
            flash(f"Archive Database Error: {e}", "danger")
        return redirect(url_for('archive'))

    archived = []
    if archive_engine:
        try:
            with archive_engine.connect() as c:
                archived = c.execute(text(
                    "SELECT ticket_id, status, employee_name, subject, archived_at FROM archived_tickets ORDER BY archived_at DESC")).fetchall()
        except Exception as e:
            flash(f"Archive Connection Error: {e}", "warning")

    return render_template('archive.html', archived=archived, has_archive=(archive_engine is not None))


@app.route('/audit')
@login_required
def audit():
    # Only Top-level management can see the audit trail
    if session.get('user_role', '').lower() not in ['super admin', 'admin', 'auditor']:
        flash("Access Denied.", "danger")
        return redirect(url_for('dashboard'))

    dept_filter = request.args.get('dept', '').strip()

    with engine.connect() as c:
        # Fetch departments for the filter dropdown
        depts = [r[0] for r in c.execute(text("SELECT name FROM departments ORDER BY name")).fetchall()]

        # Join Audit Log with Users table to get the department of the person who did the action
        query = """
                SELECT a.*, u.department
                FROM audit_log a
                         JOIN users u ON a.username = u.username
                WHERE 1 = 1 \
                """
        params = {}

        if dept_filter:
            query += " AND u.department = :d"
            params['d'] = dept_filter

        logs = c.execute(text(query + " ORDER BY a.timestamp DESC LIMIT 500"), params).fetchall()

    return render_template('audit.html', logs=logs, depts=depts, current_dept=dept_filter)

# ==========================================
# ADD THIS NEW SEARCH FUNCTIONALITY
# ==========================================

# --- UPDATE IN app.py: Search Route ---
@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '').strip()
    if not query:
        return redirect(url_for('dashboard'))

    clean_query = query.replace('#', '').replace('TICK-', '')
    role = session.get('user_role', '').lower()
    current_username = session.get('username')
    is_management = role in ['admin', 'super admin', 'it support']

    ticket_restriction = "" if is_management else "AND employee_name = :username"
    asset_restriction = "" if is_management else "AND assigned_user = :username"

    sql = text(f"""
        -- 1. Search Ticket Data
        SELECT 'ticket' as type, ticket_id as id, subject as title, 
               employee_name || ' (' || department || ')' as subtitle, 
               status as meta, created_at
        FROM tickets
        WHERE (CAST(ticket_id AS TEXT) ILIKE :q OR subject ILIKE :q OR employee_name ILIKE :q)
        {ticket_restriction}

        UNION ALL

        -- 2. Search IT Projects (NEW INTEGRATION)
        SELECT 'it_project' as type, id, title, 
               'Lead: ' || lead_it as subtitle, status as meta, created_at
        FROM it_projects
        WHERE (title ILIKE :q OR description ILIKE :q OR lead_it ILIKE :q OR co_head_it ILIKE :q)

        UNION ALL

        -- 3. Search Directory
        SELECT 'directory' as type, id, name as title, 
               department as subtitle, email as meta, NULL as created_at
        FROM company_directory
        WHERE name ILIKE :q OR department ILIKE :q OR email ILIKE :q

        UNION ALL

        -- 4. Search Asset Data
        SELECT 'asset' as type, asset_id as id, asset_tag as title, 
               asset_type as subtitle, 'User: ' || assigned_user as meta, NULL as created_at
        FROM assets
        WHERE (asset_tag ILIKE :q OR asset_type ILIKE :q OR assigned_user ILIKE :q)
        {asset_restriction}
    """)

    try:
        with engine.connect() as conn:
            results = conn.execute(sql, {"q": f"%{clean_query}%", "username": current_username}).fetchall()
    except Exception as e:
        flash(f"Search error: {e}", "danger")
        results = []

    return render_template('search_results.html', query=query, results=results)


@app.route('/role_settings', methods=['GET', 'POST'])
@login_required
def role_settings():
    # Only super admin or admin should configure this page
    if session.get('user_role', '').lower() not in ['super admin', 'admin']:
        flash("Access Denied: You do not have permission to change roles.", "danger")
        return redirect(url_for('dashboard'))

    # All available roles in your company
    roles = ['user', 'manager', 'management', 'it support', 'admin', 'super admin']

    # The sections of the sidebar we want to control
    features = [
        {'id': 'menu_directory', 'name': 'Team Directory'},
        {'id': 'menu_ier_b', 'name': 'IER Form B Approvals'},
        {'id': 'menu_admin_tools', 'name': 'Admin Tools (Analytics, Users, Assets, etc)'},
        {'id': 'menu_ier_hub', 'name': 'Asset Dept: IER Records Hub'},  # <--- NEW
        # Add this to your features list
        {'id': 'menu_it_projects', 'name': 'IT Project Management (Kanban)'}
    ]

    if request.method == 'POST':
        new_perms = {}
        for f in features:
            # Grab all checked checkboxes for this specific feature
            new_perms[f['id']] = request.form.getlist(f"perm_{f['id']}")

        try:
            with engine.begin() as c:
                # Save as a JSON string into your system_settings table
                c.execute(text("""
                               INSERT INTO system_settings (setting_key, setting_value)
                               VALUES ('role_permissions', :val) ON CONFLICT(setting_key) DO
                               UPDATE SET setting_value=EXCLUDED.setting_value
                               """), {"val": json.dumps(new_perms)})

            log_audit(session['username'], "UPDATE_ROLE_MATRIX", "System")
            flash("Role permissions updated successfully!", "success")
        except Exception as e:
            flash(f"Error saving permissions: {e}", "danger")

        return redirect(url_for('role_settings'))

    current_perms = get_role_permissions()
    return render_template('role_settings.html', roles=roles, features=features, current_perms=current_perms)

@app.route('/settings', methods=['GET', 'POST'])
@admin_required
def settings():
    if request.method == 'POST':
        action = request.form.get('action')
        try:
            with engine.begin() as c:
                if action == 'save_smtp':
                    for k in ['smtp_server', 'smtp_port', 'sender_email', 'sender_password', 'admin_email']:
                        c.execute(text(
                            "INSERT INTO system_settings (setting_key, setting_value) VALUES (:k, :v) ON CONFLICT(setting_key) DO UPDATE SET setting_value=EXCLUDED.setting_value"),
                                  {"k": k, "v": request.form.get(k, '')})
                    log_audit(session['username'], "UPDATE_SETTINGS", "System")
                    flash("System settings saved successfully.", "success")

                elif action == 'wipe_db' and request.form.get('password') == 'Itadmin':
                    for table in ["audit_log", "ticket_assets", "ticket_comments", "tickets", "ier_forms_a",
                                  "ier_forms_b"]:
                        c.execute(text(f"TRUNCATE TABLE {table} RESTART IDENTITY CASCADE;"))
                    log_audit(session['username'], "WIPE_LIVE_DATABASE", "System")
                    flash("Database successfully wiped.", "warning")
                elif action == 'wipe_db':
                    flash("Invalid Admin Password.", "danger")
        except Exception as e:
            flash(f"Settings Error: {e}", "danger")
        return redirect(url_for('settings'))

    with engine.connect() as c:
        try:
            res = c.execute(text("SELECT setting_key, setting_value FROM system_settings")).fetchall()
            st = {k: v for k, v in res}
        except Exception:
            st = {}

    return render_template('settings.html', st=st)


@app.route('/import_tickets', methods=['POST'])
@admin_required
def import_tickets():
    if 'csv_file' not in request.files:
        flash("No file found", "danger")
        return redirect(url_for('dashboard'))

    file = request.files['csv_file']
    if not file.filename.endswith('.csv'):
        flash("Please upload a CSV file.", "danger")
        return redirect(url_for('dashboard'))

    try:
        # Use utf-8-sig to handle the hidden characters (BOM) at the start of Excel CSVs
        stream = io.StringIO(file.stream.read().decode("utf-8-sig"), newline=None)
        reader = csv.DictReader(stream)

        count = 0
        with engine.begin() as conn:
            for row in reader:
                # 1. Handle the dates
                try:
                    created_at = datetime.strptime(row.get('Timestamp', ''), '%m/%d/%Y %H:%M')
                except:
                    created_at = datetime.now()

                resolved_at = None
                if row.get('COMPLETED DATE w/ Time'):
                    try:
                        resolved_at = datetime.strptime(row.get('COMPLETED DATE w/ Time', ''), '%m/%d/%Y %H:%M')
                    except:
                        resolved_at = None

                # 2. Determine Status
                status = "Resolved" if row.get('WORK DONE') or resolved_at else "New"

                # 3. Build the data dictionary and execute SQL
                # Ensure 'Target Department' matches the header in your CSV file
                conn.execute(text("""
                    INSERT INTO tickets (
                        employee_name, department, target_department, anydesk_id, email, 
                        subject, category, priority, description, status, 
                        resolution_notes, resolution_due, created_at, resolved_at, 
                        assigned_it, ticket_type, requester_ip_address
                    ) VALUES (
                        :emp, :dept, :t_dept, :any, :email, 
                        :sub, :cat, :prio, :desc, :stat, 
                        :notes, :due, :created, :resolved, 
                        :it, :tt, :ip
                    )
                """), {
                    "emp": row.get('Employee Name', 'Legacy User'),
                    "dept": row.get('Department', 'General'),
                    "t_dept": row.get('Target Department', 'IT'),
                    "any": row.get('Anydesk ID of computer', 'N/A'),
                    "email": row.get('Email address to contact', 'no-email@polycolor.biz'),
                    "sub": row.get('Subject of your concern', 'No Subject'),
                    "cat": row.get('Category', 'Technical Support'),
                    "prio": "Medium",
                    "desc": row.get('Please explain your concern', 'No description.'),
                    "stat": status,
                    "notes": row.get('WORK DONE', ''),
                    "due": created_at + timedelta(days=3),
                    "created": created_at,
                    "resolved": resolved_at,
                    "it": row.get('Assigned IT', 'System'),
                    "tt": row.get('Type', 'Incident'),
                    "ip": "0.0.0.0"
                })
                count += 1

        flash(f"Successfully imported {count} tickets!", "success")
        log_audit(session.get('username'), "BULK_IMPORT", "System", details=f"Imported {count} rows via CSV.")

    except Exception as e:
        flash(f"Import Error: {e}", "danger")
        print(f"Detailed Error: {e}")

    return redirect(url_for('dashboard'))


@app.route('/resolve_legacy', methods=['POST'])
@admin_required
def resolve_legacy():
    try:
        with engine.begin() as conn:
            # This query finds all tickets imported with the '0.0.0.0' IP
            # that are still 'New' or 'In Progress' and closes them.
            result = conn.execute(text("""
                                       UPDATE tickets
                                       SET status           = 'Resolved',
                                           resolution_notes = CASE
                                                                  WHEN resolution_notes IS NULL OR resolution_notes = ''
                                                                      THEN 'Auto-resolved during legacy data migration.'
                                                                  ELSE resolution_notes
                                               END,
                                           resolved_at      = CASE
                                                                  WHEN resolved_at IS NULL THEN created_at
                                                                  ELSE resolved_at
                                               END
                                       WHERE requester_ip_address = '0.0.0.0'
                                         AND status NOT IN ('Resolved', 'Rejected')
                                       """))
            count = result.rowcount

        flash(f"Success! {count} legacy tickets have been moved to Resolved.", "success")
        log_audit(session['username'], "BULK_RESOLVE_LEGACY", "System", details=f"Processed {count} tickets.")
    except Exception as e:
        flash(f"Resolution Error: {e}", "danger")

    return redirect(url_for('dashboard'))


@app.route('/it_projects', methods=['GET', 'POST'])
@login_required
def it_projects():
    # 1. SETUP SESSION CONTEXT
    role = session.get('user_role', '').lower()
    user_dept = session.get('user_department', 'General')
    username = session.get('username')
    full_name = session.get('full_name', username)

    # 2. DETERMINE VIEW FILTER (Inter-Departmental Logic)
    # Admins/Super Admins can switch views via ?dept=
    # Regular users/managers are locked to their own department
    if role in ['super admin', 'admin']:
        selected_dept = request.args.get('dept', 'All')
    else:
        selected_dept = user_dept

    # 3. HANDLE ACTIONS (POST)
    if request.method == 'POST':
        action = request.form.get('action')
        try:
            with engine.begin() as conn:
                # ACTION: ADD NEW PROJECT
                if action == 'add_project':
                    conn.execute(text("""
                                      INSERT INTO it_projects (title, description, status, priority, start_date,
                                                               end_date, lead_it, co_head_it, department)
                                      VALUES (:t, :d, :s, :p, :sd, :ed, :l, :ch, :dept)
                                      """), {
                                     "t": request.form.get('title'),
                                     "d": request.form.get('description'),
                                     "s": request.form.get('status', 'Planning'),
                                     "p": request.form.get('priority', 'Medium'),
                                     "sd": request.form.get('start_date') or datetime.now().date(),
                                     "ed": request.form.get('end_date') or (datetime.now() + timedelta(days=30)).date(),
                                     "l": request.form.get('lead_it'),
                                     "ch": request.form.get('co_head_it', ''),
                                     "dept": request.form.get('department', user_dept)
                                 })
                    log_audit(username, "CREATE_PROJECT", "Project", details=request.form.get('title'))
                    flash("New project launched successfully!", "success")

                # ACTION: EDIT EXISTING PROJECT
                elif action == 'edit_project':
                    conn.execute(text("""
                                      UPDATE it_projects
                                      SET title=:t,
                                          description=:d,
                                          priority=:p,
                                          status=:s,
                                          start_date=:sd,
                                          end_date=:ed,
                                          lead_it=:l,
                                          co_head_it=:ch,
                                          department=:dept
                                      WHERE id = :id
                                      """), {
                                     "t": request.form.get('title'),
                                     "d": request.form.get('description'),
                                     "p": request.form.get('priority'),
                                     "s": request.form.get('status'),
                                     "sd": request.form.get('start_date'),
                                     "ed": request.form.get('end_date'),
                                     "l": request.form.get('lead_it'),
                                     "ch": request.form.get('co_head_it'),
                                     "dept": request.form.get('department'),
                                     "id": request.form.get('id')
                                 })
                    log_audit(username, "EDIT_PROJECT", "Project", target_id=request.form.get('id'))
                    flash("Project specifications updated.", "success")

                # ACTION: DELETE PROJECT
                elif action == 'delete_project':
                    pid = request.form.get('id')
                    # Delete updates first due to Foreign Key constraints
                    conn.execute(text("DELETE FROM it_project_updates WHERE project_id = :id"), {"id": pid})
                    conn.execute(text("DELETE FROM it_projects WHERE id = :id"), {"id": pid})
                    log_audit(username, "DELETE_PROJECT", "Project", target_id=pid)
                    flash("Project permanently removed from roadmap.", "warning")

                # ACTION: ADD LOG UPDATE (Meeting Log)
                elif action == 'add_update':
                    conn.execute(text("""
                                      INSERT INTO it_project_updates (project_id, update_text, author)
                                      VALUES (:pid, :txt, :auth)
                                      """), {
                                     "pid": request.form.get('id'),
                                     "txt": request.form.get('update_text'),
                                     "auth": full_name
                                 })
                    flash("Project log updated.", "success")

        except Exception as e:
            print(f"Project Logic Error: {e}")
            flash(f"Error processing project action: {e}", "danger")

        # Redirect back to keep the filter active
        return redirect(url_for('it_projects', dept=selected_dept))

    # 4. DATA FETCHING (GET)
    with engine.connect() as conn:
        # Build Base Project Query
        query_str = "SELECT * FROM it_projects WHERE 1=1"
        params = {}

        # Apply Department Filter
        if selected_dept != 'All':
            query_str += " AND department = :dept"
            params['dept'] = selected_dept  # FIX: Explicitly binding the parameter

        # Fetch Projects
        projects = conn.execute(text(query_str + " ORDER BY priority DESC, created_at DESC"), params).fetchall()

        # Fetch all updates for all projects
        updates = conn.execute(text("SELECT * FROM it_project_updates ORDER BY created_at DESC")).fetchall()

        # Fetch Department List for Dropdowns
        depts_list = [r[0] for r in conn.execute(text("SELECT name FROM departments ORDER BY name")).fetchall()]

        # Fetch Staff List (Pulls from Users so any department member can lead)
        staff_list = conn.execute(text("""
                                       SELECT full_name as it_name
                                       FROM users
                                       ORDER BY full_name ASC
                                       """)).fetchall()

    return render_template('it_projects.html',
                           projects=projects,
                           updates=updates,
                           it_staff=staff_list,
                           depts_list=depts_list,
                           selected_dept=selected_dept)


@app.route('/it_project_analytics')
@login_required
def it_project_analytics():
    # 1. SETUP SESSION CONTEXT
    role = session.get('user_role', '').lower()
    user_dept = session.get('user_department', 'General')

    # 2. DETERMINE DEPARTMENT SCOPE
    # Admins see Global/All by default. Managers/Users see their own department.
    if role in ['super admin', 'admin']:
        selected_dept = request.args.get('dept', 'All')
    else:
        selected_dept = user_dept

    with engine.connect() as conn:
        # 3. BUILD QUERY BASE & PARAMETERS
        # This structure prevents the "A value is required for bind parameter" error
        base_sql = " WHERE 1=1 "
        params = {}

        if selected_dept != 'All':
            base_sql += " AND department = :dept "
            params['dept'] = selected_dept

        # --- STATS CALCULATION ---
        total = conn.execute(text(f"SELECT COUNT(*) FROM it_projects {base_sql}"), params).scalar() or 0
        active = conn.execute(
            text(f"SELECT COUNT(*) FROM it_projects {base_sql} AND status IN ('In Progress', 'Testing')"),
            params).scalar() or 0
        completed = conn.execute(text(f"SELECT COUNT(*) FROM it_projects {base_sql} AND status = 'Completed'"),
                                 params).scalar() or 0

        # --- CHART 1: PROJECT PULSE (STATUS DISTRIBUTION) ---
        status_res = conn.execute(text(f"""
            SELECT status, COUNT(*) 
            FROM it_projects 
            {base_sql} 
            GROUP BY status
        """), params).fetchall()

        # --- CHART 2: LEAD WORKLOAD (ACTIVE PROJECTS) ---
        # We only show workload for projects that are not finished
        workload_res = conn.execute(text(f"""
            SELECT lead_it, COUNT(*) as count 
            FROM it_projects 
            {base_sql} AND status != 'Completed' 
            GROUP BY lead_it 
            ORDER BY count DESC LIMIT 5
        """), params).fetchall()

        # --- CHART 3: PRIORITY HEATMAP ---
        prio_res = conn.execute(text(f"""
            SELECT priority, COUNT(*) 
            FROM it_projects 
            {base_sql} 
            GROUP BY priority
        """), params).fetchall()

        # --- LIST: CRITICAL DEADLINES ---
        upcoming = conn.execute(text(f"""
            SELECT title, end_date, status, priority 
            FROM it_projects 
            {base_sql} AND status != 'Completed' 
            ORDER BY end_date ASC LIMIT 5
        """), params).fetchall()

        # --- DATA FOR DROPDOWN ---
        depts_list = [r[0] for r in conn.execute(text("SELECT name FROM departments ORDER BY name")).fetchall()]

    # 4. RENDER TEMPLATE WITH FILTERED DATA
    return render_template('it_project_analytics.html',
                           total=total,
                           active=active,
                           completed=completed,
                           status_labels=[r[0] for r in status_res],
                           status_values=[r[1] for r in status_res],
                           workload_labels=[r[0] for r in workload_res],
                           workload_values=[r[1] for r in workload_res],
                           prio_labels=[r[0] for r in prio_res],
                           prio_values=[r[1] for r in prio_res],
                           upcoming=upcoming,
                           selected_dept=selected_dept,
                           depts_list=depts_list)


@app.route('/api/analytics/drilldown/<type>')
@login_required
def api_drilldown(type):
    START_DATE = datetime(2026, 3, 23)
    data_list = []

    with engine.connect() as conn:
        try:
            if type == 'total_volume':
                # Group by Department
                query = text("""
                             SELECT department, COUNT(*) as c
                             FROM tickets
                             WHERE created_at >= :sd
                             GROUP BY department
                             ORDER BY c DESC
                             """)
                res = conn.execute(query, {"sd": START_DATE}).fetchall()
                data_list = [{"label": r[0] if r[0] else "Unassigned", "value": r[1]} for r in res]

            elif type == 'overdue_workload':
                # Group by IT Staff for Overdue tickets
                query = text("""
                             SELECT assigned_it, COUNT(*) as c
                             FROM tickets
                             WHERE status NOT IN ('Resolved', 'Rejected')
                               AND resolution_due < CURRENT_TIMESTAMP
                               AND created_at >= :sd
                             GROUP BY assigned_it
                             ORDER BY c DESC
                             """)
                res = conn.execute(query, {"sd": START_DATE}).fetchall()
                data_list = [{"label": r[0] if r[0] else "Unassigned", "value": r[1]} for r in res]

            elif type == 'sla_breaches':
                # List of specific tickets that failed SLA
                query = text("""
                             SELECT ticket_id, subject, resolution_due
                             FROM tickets
                             WHERE created_at >= :sd
                               AND (
                                 (status = 'Resolved' AND resolved_at > resolution_due) OR
                                 (status NOT IN ('Resolved', 'Rejected') AND CURRENT_TIMESTAMP > resolution_due)
                                 )
                             ORDER BY resolution_due ASC LIMIT 50
                             """)
                res = conn.execute(query, {"sd": START_DATE}).fetchall()
                data_list = [{"id": r[0], "subject": r[1], "date": r[2].strftime('%b %d')} for r in res]

            elif type == 'avg_resolution':
                # List of resolved tickets (shows speed/efficiency)
                query = text("""
                             SELECT ticket_id, subject, created_at
                             FROM tickets
                             WHERE status = 'Resolved'
                               AND created_at >= :sd
                             ORDER BY resolved_at DESC LIMIT 50
                             """)
                res = conn.execute(query, {"sd": START_DATE}).fetchall()
                data_list = [{"id": r[0], "subject": r[1], "date": r[2].strftime('%b %d')} for r in res]

            return jsonify(data_list)

        except Exception as e:
            print(f"Drilldown API Error: {e}")
            return jsonify([]), 500


@app.route('/api/analytics/details/<filter_type>')
@login_required
def analytics_details_api(filter_type):
    # 1. Get the department from the URL (?dept=Accounting)
    selected_dept = request.args.get('dept', 'All')
    START_DATE = datetime(2026, 3, 23)

    # 2. Base Query
    query = "SELECT ticket_id, subject, employee_name, status, created_at FROM tickets WHERE created_at >= :sd"
    params = {"sd": START_DATE}

    # 3. Apply Department Filter
    if selected_dept != 'All':
        query += " AND target_department = :dept"
        params['dept'] = selected_dept

    # 4. Apply Status Category Filter
    if filter_type == 'open':
        query += " AND status IN ('New', 'In Progress', 'Re-Opened', 'Pending Approval')"
    elif filter_type == 'resolved':
        query += " AND status = 'Resolved'"
    elif filter_type == 'breached':
        # Correct SLA Breach logic for the modal
        query += """ AND (
            (status = 'Resolved' AND resolved_at > resolution_due) OR 
            (status NOT IN ('Resolved', 'Rejected') AND CURRENT_TIMESTAMP > resolution_due)
        )"""

    with engine.connect() as conn:
        res = conn.execute(text(query + " ORDER BY created_at DESC LIMIT 100"), params).fetchall()
        return jsonify([{
            "id": r[0],
            "subject": r[1],
            "name": r[2],
            "status": r[3],
            "date": r[4].strftime('%Y-%m-%d')
        } for r in res])


@app.route('/api/sla/drilldown/<type>')
@login_required
def api_sla_drilldown(type):
    # 1. Capture filters
    selected_dept = request.args.get('dept', 'All')
    START_DATE = datetime(2026, 3, 23)

    # 2. Base Query Logic
    # We filter by target_department because SLA measures the RECEIVING department's speed.
    base_sql = "WHERE created_at >= :sd"
    params = {"sd": START_DATE}

    if selected_dept != 'All':
        base_sql += " AND target_department = :dept"
        params['dept'] = selected_dept

    with engine.connect() as conn:
        # --- CASE A: Ticket Volume Breakdown (Summary Table) ---
        if type == 'total_volume':
            sql = f"""SELECT department as label, COUNT(*) as value 
                      FROM tickets {base_sql} 
                      GROUP BY department ORDER BY value DESC"""
            res = conn.execute(text(sql), params).fetchall()
            return jsonify([{"label": r[0], "value": r[1]} for r in res])

        # --- CASE B: SLA Breaches (Detailed List) ---
        elif type == 'sla_breaches':
            sql = f"""SELECT ticket_id, subject, resolution_due, employee_name 
                      FROM tickets {base_sql} 
                      AND (
                          (status = 'Resolved' AND resolved_at > resolution_due) OR 
                          (status NOT IN ('Resolved', 'Rejected') AND CURRENT_TIMESTAMP > resolution_due)
                      ) ORDER BY resolution_due ASC"""
            res = conn.execute(text(sql), params).fetchall()
            return jsonify(
                [{"id": r[0], "subject": r[1], "date": r[2].strftime('%b %d, %H:%M'), "name": r[3]} for r in res])

        # --- CASE C: Overdue Workload (Detailed List) ---
        elif type == 'overdue_workload':
            sql = f"""SELECT ticket_id, subject, resolution_due, assigned_it 
                      FROM tickets {base_sql} 
                      AND status NOT IN ('Resolved', 'Rejected') 
                      AND resolution_due < CURRENT_TIMESTAMP 
                      ORDER BY resolution_due ASC"""
            res = conn.execute(text(sql), params).fetchall()
            return jsonify(
                [{"id": r[0], "subject": r[1], "date": r[2].strftime('%b %d'), "name": r[3] or 'Unassigned'} for r in
                 res])

        # --- CASE D: Average Resolution List ---
        elif type == 'avg_resolution':
            sql = f"""SELECT ticket_id, subject, resolved_at, employee_name 
                      FROM tickets {base_sql} 
                      AND status = 'Resolved' 
                      ORDER BY resolved_at DESC LIMIT 50"""
            res = conn.execute(text(sql), params).fetchall()
            return jsonify([{"id": r[0], "subject": r[1], "date": r[2].strftime('%b %d'), "name": r[3]} for r in res])

    return jsonify([])

# --- NEW API: Get Users by Department ---
@app.route('/api/get_users_by_dept/<dept_name>')
@login_required
def get_users_by_dept(dept_name):
    """Fetches users, filtering out empty or null names to prevent blank gaps."""
    with engine.connect() as conn:
        res = conn.execute(
            text("""
                SELECT username, full_name 
                FROM users 
                WHERE TRIM(department) ILIKE TRIM(:d) 
                AND full_name IS NOT NULL 
                AND full_name != '' 
                AND full_name != ' '
                ORDER BY full_name ASC
            """),
            {"d": dept_name}
        ).fetchall()
        return jsonify([{"username": r.username, "full_name": r.full_name} for r in res])

# --- NEW API: Get Ticket Types by Department ---
@app.route('/api/get_types_by_dept/<dept_name>')
@login_required
def get_types_by_dept(dept_name):
    with engine.connect() as conn:
        res = conn.execute(
            text("SELECT type_name FROM department_ticket_types WHERE department_name = :d"),
            {"d": dept_name}
        ).fetchall()
        # Fallback to standard types if none defined for dept
        if not res:
            return jsonify([{"name": t} for t in ['Incident', 'Request', 'Inquiry', 'Change']])
        return jsonify([{"name": r.type_name} for r in res])


@app.route('/manage_ticket_types', methods=['GET', 'POST'])
@login_required
@admin_required  # Ensure only admins can access
def manage_ticket_types():
    if request.method == 'POST':
        action = request.form.get('action')
        dept = request.form.get('department_name')
        t_type = request.form.get('type_name')
        type_id = request.form.get('id')

        try:
            with engine.begin() as conn:
                if action == 'add':
                    conn.execute(
                        text("INSERT INTO department_ticket_types (department_name, type_name) VALUES (:d, :t)"),
                        {"d": dept, "t": t_type})
                    flash(f"Added '{t_type}' to {dept}", "success")

                elif action == 'edit':
                    conn.execute(
                        text("UPDATE department_ticket_types SET department_name=:d, type_name=:t WHERE id=:id"),
                        {"d": dept, "t": t_type, "id": type_id})
                    flash("Ticket type updated.", "success")

                elif action == 'delete':
                    conn.execute(text("DELETE FROM department_ticket_types WHERE id=:id"), {"id": type_id})
                    flash("Ticket type removed.", "info")
        except Exception as e:
            flash(f"Error: {e}", "danger")
        return redirect(url_for('manage_ticket_types'))

    with engine.connect() as conn:
        # Get all departments for the dropdown
        depts = [r[0] for r in conn.execute(text("SELECT name FROM departments ORDER BY name")).fetchall()]
        # Get all current ticket types
        types = conn.execute(
            text("SELECT * FROM department_ticket_types ORDER BY department_name, type_name")).fetchall()

    return render_template('manage_ticket_types.html', depts=depts, ticket_types=types)

@app.route('/import_users', methods=['POST'])
@admin_required
def import_users():
    if 'csv_file' not in request.files:
        flash("No file found", "danger")
        return redirect(url_for('users'))

    file = request.files['csv_file']
    if not file.filename.endswith('.csv'):
        flash("Please upload a CSV file.", "danger")
        return redirect(url_for('users'))

    try:
        # Read the CSV
        stream = io.StringIO(file.stream.read().decode("utf-8-sig"), newline=None)
        reader = csv.DictReader(stream)

        # Default password for all new imported users
        default_pass = "Welcome@CCI2024"
        hashed_pass = bcrypt.hashpw(default_pass.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        count = 0
        skipped = 0

        with engine.begin() as conn:
            for row in reader:
                username = row.get('username', '').lower().strip()
                if not username:
                    continue

                # Check if user already exists to avoid crashes
                exists = conn.execute(text("SELECT 1 FROM users WHERE username = :u"), {"u": username}).scalar()

                if exists:
                    skipped += 1
                    continue

                conn.execute(text("""
                                  INSERT INTO users (username, full_name, email, password_hash, role, department)
                                  VALUES (:u, :fn, :e, :p, :r, :d)
                                  """), {
                                 "u": username,
                                 "fn": row.get('full_name', username),
                                 "e": row.get('email', ''),
                                 "p": hashed_pass,
                                 "r": row.get('role', 'user').lower(),
                                 "d": row.get('department', 'General')
                             })
                count += 1

        flash(f"Import Complete! Created {count} users. Skipped {skipped} existing users.", "success")
        flash(f"All new users have the default password: {default_pass}", "info")
        log_audit(session['username'], "BULK_USER_IMPORT", "System", details=f"Imported {count} users.")

    except Exception as e:
        flash(f"Import Error: {e}", "danger")

    return redirect(url_for('users'))

if __name__ == '__main__':
    # Change debug=True to debug=False and add host='0.0.0.0'
    socketio.run(app, debug=False, host='0.0.0.0', port=5000)