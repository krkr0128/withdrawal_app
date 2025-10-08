# app.py — 出金管理（完了・差し戻しのワンクリ運用＋権限分離）
# ----------------------------------------------------------
# 機能
# - ログイン / ログアウト / 初期セットアップ（初回ユーザー=admin）
# - 管理者/作業者の権限分離（CSV入出力・ユーザー管理は admin 限定）
# - 出金一覧（完了・差し戻しをワンクリ更新）
# - ステータス別に色分け（完了＝灰、差し戻し＝淡オレンジ）
# - ユーザー管理（一覧・作成・ロール変更・PW再設定）
# ----------------------------------------------------------

from __future__ import annotations
import io, csv, os, re
from datetime import datetime, date, timedelta
from dateutil import parser as dtparse
from flask import Flask, request, redirect, url_for, render_template_string, send_file, session, jsonify, flash
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, func, and_, or_, text
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from markupsafe import Markup, escape

# ===== 設定 =====
DB_URL = os.environ.get("DATABASE_URL", "sqlite:///data.sqlite3")
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret")

engine = create_engine(DB_URL, connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {})
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine)

# ===== モデル =====
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False)
    name = Column(String(100))
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="worker")  # admin / worker
    created_at = Column(DateTime, default=datetime.utcnow)

    @staticmethod
    def create(session, email: str, password: str, name: str = "", role: str = "worker"):
        u = User(
            email=email.lower().strip(),
            name=name,
            password_hash=generate_password_hash(password),
            role=role,
        )
        session.add(u)
        session.commit()
        return u

    def verify(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

class Withdrawal(Base):
    __tablename__ = "withdrawals"
    id = Column(Integer, primary_key=True)
    client = Column(String(32))
    no = Column(String(64))
    applied_at = Column(DateTime)
    bank_name = Column(String(128))
    branch_name = Column(String(128))
    account_type = Column(String(64))
    account_number = Column(String(64))
    account_holder = Column(String(128))
    amount = Column(Float)
    payout_account = Column(String(128))
    status = Column(String(32))
    owner = Column(String(64))
    memo = Column(Text)
    updated_at = Column(DateTime, default=datetime.utcnow)
    last_changed_by = Column(String(255))
    last_changed_at = Column(DateTime)

Base.metadata.create_all(engine)

# --- 既存DBに role 列を自動付与 & 未設定は admin に
def ensure_user_role_column():
    try:
        if DB_URL.startswith("sqlite"):
            with engine.connect() as con:
                cols = [row[1] for row in con.exec_driver_sql("PRAGMA table_info(users)").fetchall()]
                if "role" not in cols:
                    con.exec_driver_sql("ALTER TABLE users ADD COLUMN role VARCHAR(20)")
                con.exec_driver_sql("UPDATE users SET role='admin' WHERE role IS NULL OR role=''")
                con.commit()
    except Exception as e:
        print("ensure_user_role_column:", e)

ensure_user_role_column()

# ===== Flask =====
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.jinja_env.globals['int'] = int  # Jinjaでintを使えるように

# ===== ログイン保護 =====
def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not session.get("user"):
            return redirect(url_for("login", next=request.path))
        return fn(*a, **kw)
    return wrapper

# 権限チェック
def require_role(role_name):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = session.get("user")
            if not user:
                return redirect(url_for("login"))
            if role_name == "admin" and user.get("role") != "admin":
                return "権限がありません（管理者専用）", 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# ===== 認証ルート =====
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email") or "").lower().strip()
        pw = request.form.get("password") or ""
        db = SessionLocal()
        u = db.query(User).filter(User.email == email).first()
        if u and u.verify(pw):
            session["user"] = {"email": u.email, "name": u.name or u.email, "role": (u.role or "worker")}
            db.close()
            return redirect(request.args.get("next") or "/")
        db.close()
        flash("メールまたはパスワードが違います", "error")
    return render_template_string(TPL_LOGIN)

@app.route("/logout")
@login_required
def logout():
    session.pop("user", None)
    return redirect("/login")

@app.route("/setup", methods=["GET", "POST"])
def setup():
    db = SessionLocal()
    if db.query(User).count() > 0:
        db.close()
        return redirect("/login")
    if request.method == "POST":
        # 初回ユーザーは管理者に
        User.create(db, request.form["email"], request.form["password"], request.form.get("name", ""), role="admin")
        db.close()
        return redirect("/login")
    db.close()
    return render_template_string(TPL_SETUP)

# ===== ユーザー管理（admin専用） =====
@app.route("/users")
@login_required
@require_role("admin")
def users_page():
    db = SessionLocal()
    users = db.query(User).order_by(User.created_at.desc()).all()
    db.close()
    return render_template_string(TPL_USERS, users=users, user=session["user"])

@app.route("/users/create", methods=["POST"])
@login_required
@require_role("admin")
def users_create():
    email = (request.form.get("email") or "").strip().lower()
    name = (request.form.get("name") or "").strip()
    password = request.form.get("password") or ""
    role = request.form.get("role") or "worker"
    if not email or not password:
        return redirect(url_for("users_page", msg="メール/パスワード必須"))
    db = SessionLocal()
    try:
        User.create(db, email, password, name, role)
        return redirect(url_for("users_page", ok="1"))
    except IntegrityError:
        db.rollback()
        return redirect(url_for("users_page", msg="既に登録済みのメールです"))
    finally:
        db.close()

@app.route("/users/role", methods=["POST"])
@login_required
@require_role("admin")
def users_set_role():
    uid = int(request.form["id"])
    role = request.form.get("role") or "worker"
    db = SessionLocal()
    u = db.get(User, uid)
    if not u:
        db.close()
        return redirect(url_for("users_page", msg="ユーザーが見つかりません"))
    u.role = role
    db.commit()
    db.close()
    return redirect(url_for("users_page", ok="1"))

@app.route("/users/resetpw", methods=["POST"])
@login_required
@require_role("admin")
def users_resetpw():
    uid = int(request.form["id"])
    pw = request.form.get("password") or ""
    if not pw:
        return redirect(url_for("users_page", msg="パスワード必須"))
    db = SessionLocal()
    u = db.get(User, uid)
    if not u:
        db.close()
        return redirect(url_for("users_page", msg="ユーザーが見つかりません"))
    u.password_hash = generate_password_hash(pw)
    db.commit()
    db.close()
    return redirect(url_for("users_page", ok="1"))

# ===== メイン =====
@app.route("/")
@login_required
def index():
    db = SessionLocal()
    rows = db.query(Withdrawal).order_by(Withdrawal.applied_at.desc()).all()

    today0 = datetime.combine(date.today(), datetime.min.time())
    today1 = today0 + timedelta(days=1)
    t_q = db.query(func.count(Withdrawal.id), func.coalesce(func.sum(Withdrawal.amount), 0.0))\
        .filter(and_(Withdrawal.applied_at >= today0, Withdrawal.applied_at < today1)).one()
    today_count, today_amount = t_q[0] or 0, int(t_q[1] or 0)

    db.close()
    return render_template_string(TPL_INDEX,
                                  rows=rows,
                                  today_count=today_count,
                                  today_amount=today_amount,
                                  user=session.get("user"))

# ===== ステータス更新 =====
@app.route("/toggle_status", methods=["POST"])
@login_required
def toggle_status():
    id_ = int(request.form["id"])
    next_ = request.form["next"]
    db = SessionLocal()
    obj = db.get(Withdrawal, id_)
    if not obj:
        db.close()
        return jsonify({"ok": False})
    obj.status = next_
    obj.last_changed_by = session["user"]["email"]
    obj.last_changed_at = datetime.utcnow()
    obj.updated_at = datetime.utcnow()
    db.commit()
    db.close()
    return jsonify({"ok": True, "status": next_})

# ===== CSVアップロード =====
@app.route("/upload", methods=["POST"])
@login_required
@require_role("admin")
def upload():
    file = request.files["file"]
    text = file.stream.read().decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(text))
    db = SessionLocal()
    for row in reader:
        if all((not str(v).strip() for v in row.values())):
            continue
        no_ = str(row.get("No.") or "").strip()
        obj = db.query(Withdrawal).filter(Withdrawal.no == no_).first() or Withdrawal(no=no_)
        obj.client = (row.get("クライアント") or "").strip()
        obj.applied_at = dtparse.parse(row.get("申請日時")) if row.get("申請日時") else None
        obj.bank_name = (row.get("銀行名") or "").strip()
        obj.branch_name = (row.get("支店名") or "").strip()
        obj.account_type = (row.get("口座種別") or "").strip()
        obj.account_number = (row.get("口座番号") or "").strip()
        obj.account_holder = (row.get("口座名義") or "").strip()
        obj.amount = float(str(row.get("金額")).replace(",", "")) if row.get("金額") else None
        obj.payout_account = (row.get("出金口座") or "").strip()
        obj.status = (row.get("ステータス") or "").strip()
        obj.owner = (row.get("担当者") or "").strip()
        obj.updated_at = datetime.utcnow()
        db.add(obj)
    db.commit()
    db.close()
    return redirect("/")

# ===== CSVエクスポート =====
@app.route("/export")
@login_required
@require_role("admin")
def export_csv():
    db = SessionLocal()
    rows = db.query(Withdrawal).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["クライアント", "No.", "申請日時", "銀行名", "支店名", "口座種別", "口座番号", "口座名義", "金額", "出金口座", "ステータス", "担当者"])
    for r in rows:
        writer.writerow([
            r.client or "", r.no or "",
            r.applied_at.strftime("%Y-%m-%d %H:%M:%S") if r.applied_at else "",
            r.bank_name or "", r.branch_name or "", r.account_type or "",
            r.account_number or "", r.account_holder or "",
            int(r.amount) if r.amount else "",
            r.payout_account or "", r.status or "", r.owner or ""
        ])
    mem = io.BytesIO(output.getvalue().encode("utf-8-sig"))
    mem.seek(0)
    db.close()
    return send_file(mem, as_attachment=True, download_name="withdrawals.csv", mimetype="text/csv")

# ===== テンプレ =====
TPL_BASE = """
<!doctype html><html lang=ja><head>
<meta charset=utf-8><meta name=viewport content="width=device-width, initial-scale=1">
<title>出金管理</title>
<link rel=stylesheet href="https://unpkg.com/@picocss/pico@2/css/pico.min.css">
<style>
body{background:#f4f6f9;font-family:"Meiryo","メイリオ",sans-serif}
.wrap{max-width:1280px;margin:auto;padding:12px}
.table-wrap{background:#fff;border:1px solid #e6eaf0;border-radius:12px;overflow:auto;box-shadow:0 2px 8px rgba(16,24,40,.04)}
th,td{padding:.6rem .8rem;white-space:nowrap;font-size:13px}

/* 行ホバー＆状態 */
tbody tr:hover{background-color:#fff9e6!important}
tr.done td{background-color:#f5f5f5!important;color:#888!important}
tr.returned td{background-color:#fff4dd!important;color:#8a5200!important}

/* ボタン・バッジ */
.btn{border-radius:999px;height:36px;padding:0 16px;border:1px solid #2276d2;background:#2276d2;color:#fff;font-size:13px}
.btn.secondary{background:#fff;color:#2276d2}
.badge{padding:.25rem .5rem;border-radius:999px;font-size:12px;border:1px solid #ddd}
.ok{color:#0b7a3f;background:rgba(37,181,98,.12);border-color:rgba(37,181,98,.25)}
.hold{color:#8a5200;background:rgba(255,159,26,.16);border-color:rgba(255,159,26,.3)}
</style>
</head><body><div class=wrap>
"""

TPL_LOGIN = TPL_BASE + """
<h2>サインイン</h2>
<form method=post style="max-width:420px">
  <label>メール<input type=email name=email required></label>
  <label>パスワード<input type=password name=password required></label>
  <button class=btn type=submit>ログイン</button>
</form></div></body></html>
"""

TPL_SETUP = TPL_BASE + """
<h2>初期セットアップ</h2>
<form method=post style="max-width:420px">
  <label>表示名<input name=name></label>
  <label>メール<input type=email name=email required></label>
  <label>パスワード<input type=password name=password required></label>
  <button class=btn type=submit>管理者作成</button>
</form></div></body></html>
"""

TPL_INDEX = TPL_BASE + """
<h2>出金一覧</h2>
<div style="display:flex;justify-content:space-between;align-items:center">
  {% set role = (user.role if user and user.role else 'worker') %}
  <div>
    {{ user.name }} ({{ '管理者' if role=='admin' else '作業者' }})
    &nbsp;/&nbsp;<a href="/logout">ログアウト</a>
  </div>
  <div style="display:flex;gap:8px;align-items:center">
    {% if role == 'admin' %}
      <a class="btn secondary" href="/users">ユーザー管理</a>
      <a class="btn secondary" href="/export">CSVエクスポート</a>
      <form id=csvForm action="/upload" method=post enctype=multipart/form-data style="display:inline;">
        <input type=file name=file accept=".csv" id=csvFile hidden onchange="csvForm.submit()">
        <button type=button class="btn secondary" onclick="csvFile.click()">CSVアップロード</button>
      </form>
    {% endif %}
  </div>
</div>

<div style="margin:10px 0;display:flex;gap:20px;">
  <div>今日の出金件数: <b>{{today_count}}</b></div>
  <div>今日の出金金額: <b>{{"{:,}".format(today_amount)}}</b>円</div>
</div>

<div class="table-wrap"><table>
  <thead><tr>
    <th>No.</th><th>申請日時</th><th>銀行名</th><th>支店名</th>
    <th>口座名義</th><th>金額</th><th>出金口座</th><th>ステータス</th><th>担当者</th><th>操作</th>
  </tr></thead>
  <tbody>
  {% for r in rows %}
  <tr data-id="{{r.id}}" class="{% if r.status=='完了' %}done{% elif r.status=='差し戻し' %}returned{% endif %}">
    <td>{{r.no or ''}}</td>
    <td>{{r.applied_at.strftime('%Y/%m/%d %H:%M') if r.applied_at else ''}}</td>
    <td>{{r.bank_name or ''}}</td>
    <td>{{r.branch_name or ''}}</td>
    <td>{{r.account_holder or ''}}</td>
    <td style="text-align:right">{{"{:,}".format(int(r.amount)) if r.amount else ''}}</td>
    <td>{{r.payout_account or ''}}</td>
    <td>
      {% if r.status=='完了' %}
        <span class="badge ok">完了</span>
      {% elif r.status=='差し戻し' %}
        <span class="badge hold">差し戻し</span>
      {% else %}
        <span class="badge">{{r.status or '—'}}</span>
      {% endif %}
    </td>
    <td>{{r.owner or ''}}</td>
    <td>
      {% if r.status not in ['完了','差し戻し'] %}
        <div style="display:flex;gap:6px;">
          <button class="btn" onclick="toggleStatus({{r.id}}, '完了', this)">完了にする</button>
          <button class="btn secondary" style="border-color:#cfa900;color:#cfa900;" onclick="toggleStatus({{r.id}}, '差し戻し', this)">差し戻しにする</button>
        </div>
      {% elif r.status=='完了' %}
        <span style="color:#6b7280;font-size:12px;">完了済み</span>
      {% elif r.status=='差し戻し' %}
        <span style="color:#8a5200;font-size:12px;">差し戻し済み</span>
      {% endif %}
    </td>
  </tr>
  {% endfor %}
  </tbody>
</table></div>

<script>
function toggleStatus(id, next, btn){
  fetch('/toggle_status',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:`id=${id}&next=${next}`})
  .then(r=>r.json()).then(data=>{
    if(data.ok){
      const tr = btn.closest('tr');
      const td = tr.querySelector('td:nth-child(8)');
      td.innerHTML = (next==='完了') ? '<span class="badge ok">完了</span>' : '<span class="badge hold">差し戻し</span>';
      tr.classList.remove('done','returned');
      if(next==='完了'){ tr.classList.add('done'); }
      if(next==='差し戻し'){ tr.classList.add('returned'); }
      btn.parentElement.innerHTML = next==='完了'
        ? '<span style="color:#6b7280;font-size:12px;">完了済み</span>'
        : '<span style="color:#8a5200;font-size:12px;">差し戻し済み</span>';
    } else { alert('更新失敗'); }
  });
}
</script>
</div></body></html>
"""

TPL_USERS = TPL_BASE + """
<h2>ユーザー管理</h2>

<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
  <div>
    {{ user.name }} ({{ '管理者' if user.role=='admin' else '作業者' }})
    &nbsp;/&nbsp;<a href="/logout">ログアウト</a>
  </div>

  <div style="display:flex;gap:8px;align-items:center">
    <a class="btn secondary" href="/users">ユーザー管理</a>
    <a class="btn secondary" href="/export">CSVエクスポート</a>
    <form id="csvForm" action="/upload" method="post" enctype="multipart/form-data" style="display:inline;">
      <input type="file" name="file" accept=".csv" id="csvFile" hidden onchange="csvForm.submit()">
      <button type="button" class="btn secondary" onclick="csvFile.click()">CSVアップロード</button>
    </form>
  </div>
</div>

{% if request.args.get('msg') %}
  <p style="color:#b91c1c;background:#fee2e2;border:1px solid #fecaca;padding:.5rem .8rem;border-radius:8px;">
    {{ request.args.get('msg') }}
  </p>
{% elif request.args.get('ok') %}
  <p style="color:#065f46;background:#ecfdf5;border:1px solid #bbf7d0;padding:.5rem .8rem;border-radius:8px;">
    反映しました。
  </p>
{% endif %}

<div class="table-wrap" style="margin-bottom:18px;">
<table>
  <thead><tr>
    <th style="width:220px">メール</th>
    <th style="width:160px">表示名</th>
    <th style="width:120px">ロール</th>
    <th style="width:140px">作成日時</th>
    <th>操作</th>
  </tr></thead>
  <tbody>
    {% for u in users %}
    <tr>
      <td>{{ u.email }}</td>
      <td>{{ u.name or '' }}</td>
      <td>
        <form method="post" action="/users/role" style="display:flex;gap:8px;align-items:center">
          <input type="hidden" name="id" value="{{ u.id }}">
          <select name="role">
            <option value="admin" {{ 'selected' if u.role=='admin' else '' }}>admin(管理者)</option>
            <option value="worker" {{ 'selected' if u.role!='admin' else '' }}>worker(作業者)</option>
          </select>
          <button class="btn secondary" style="height:30px;padding:0 10px;">変更</button>
        </form>
      </td>
      <td>{{ u.created_at.strftime('%Y/%m/%d %H:%M') if u.created_at else '' }}</td>
      <td>
        <form method="post" action="/users/resetpw" style="display:flex;gap:8px;align-items:center">
          <input type="hidden" name="id" value="{{ u.id }}">
          <input type="password" name="password" placeholder="新パスワード" required style="height:30px">
          <button class="btn" style="height:30px;padding:0 12px;">PW再設定</button>
        </form>
      </td>
    </tr>
    {% endfor %}
  </tbody>
</table>
</div>

<h3>ユーザー追加</h3>
<form method="post" action="/users/create" class="table-wrap" style="padding:12px;border-radius:12px;">
  <div class="grid">
    <label>メール<input type="email" name="email" required></label>
    <label>表示名<input type="text" name="name"></label>
    <label>パスワード<input type="password" name="password" required></label>
    <label>ロール
      <select name="role">
        <option value="worker">worker(作業者)</option>
        <option value="admin">admin(管理者)</option>
      </select>
    </label>
  </div>
  <button class="btn" type="submit">追加</button>
</form>

</div></body></html>
"""

if __name__ == "__main__":
    app.run(debug=True)
