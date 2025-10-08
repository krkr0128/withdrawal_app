# app.py — 出金管理 フル機能版
# - ログイン/ログアウト（admin / worker）
# - ユーザー管理（adminのみ）
# - CSV アップロード / エクスポート（UTF-8 BOM対応）
# - 検索・絞り込み・日付範囲・並び替え
# - ワンクリック「完了 / 差し戻し」
# - 操作履歴（誰がいつ何を）
# - 管理者のみ：一括削除（削除はアーカイブに移動）

from __future__ import annotations
import io, csv, os, re
from datetime import datetime, date, timedelta
from dateutil import parser as dtparse
from functools import wraps
from typing import Optional, List, Dict, Any

from flask import (
    Flask, request, redirect, url_for, render_template_string,
    send_file, jsonify, session, abort, flash
)
from sqlalchemy import (
    create_engine, Column, Integer, String, Float, DateTime, Text,
    func, and_, or_, desc, asc
)
from sqlalchemy.orm import declarative_base, sessionmaker
from werkzeug.security import generate_password_hash, check_password_hash

# ------------------ 設定 ------------------
DB_URL = os.environ.get("DATABASE_URL", "sqlite:///data.sqlite3")
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret")

engine = create_engine(
    DB_URL,
    connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {}
)
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine)

# ------------------ モデル ------------------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False)
    name = Column(String(100))              # 表示名（空なら email の @前 を使う）
    role = Column(String(20), default="worker")  # 'admin' or 'worker'
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    @staticmethod
    def create(session, email: str, password: str, name: str = "", role: str = "worker"):
        u = User(
            email=email.lower().strip(),
            name=(name or "").strip(),
            role=role,
            password_hash=generate_password_hash(password)
        )
        session.add(u)
        session.commit()
        return u

    def verify(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def display_name(self) -> str:
        return (self.name or self.email.split("@")[0])

class Withdrawal(Base):
    __tablename__ = "withdrawals"
    id = Column(Integer, primary_key=True)
    company = Column(String(64))            # 会社（旧: クライアント）
    no = Column(String(64))
    applied_at = Column(DateTime)
    bank_name = Column(String(128))
    branch_name = Column(String(128))
    account_type = Column(String(64))
    account_number = Column(String(64))
    account_holder = Column(String(128))
    amount = Column(Float)
    payout_account = Column(String(128))
    fee = Column(Float)
    status = Column(String(32))             # '', '完了', '差し戻し'
    owner = Column(String(64))              # 担当者（フリーテキスト）
    memo = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)
    last_changed_by = Column(String(255))
    last_changed_at = Column(DateTime)

class ArchivedWithdrawal(Base):
    """削除時にここへフルコピー（監査のため保存）"""
    __tablename__ = "archived_withdrawals"
    id = Column(Integer, primary_key=True)
    original_id = Column(Integer)           # 元のID
    company = Column(String(64))
    no = Column(String(64))
    applied_at = Column(DateTime)
    bank_name = Column(String(128))
    branch_name = Column(String(128))
    account_type = Column(String(64))
    account_number = Column(String(64))
    account_holder = Column(String(128))
    amount = Column(Float)
    payout_account = Column(String(128))
    fee = Column(Float)
    status = Column(String(32))
    owner = Column(String(64))
    memo = Column(Text)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)
    last_changed_by = Column(String(255))
    last_changed_at = Column(DateTime)
    deleted_at = Column(DateTime, default=datetime.utcnow)
    deleted_by = Column(String(255))

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, default=datetime.utcnow)
    user_email = Column(String(255))
    action = Column(String(64))            # 'status_update','upload','delete','create_user','reset_pw','role_change'
    target = Column(String(64))            # 'withdrawal:123', etc.
    detail = Column(Text)

Base.metadata.create_all(engine)

# ------------------ Flask ------------------
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.jinja_env.globals['int'] = int  # jinja2 で int を使えるように

# ------------------ ヘルパ ------------------
def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not session.get("user"):
            return redirect(url_for("login", next=request.path))
        return fn(*a, **kw)
    return wrapper

def require_role(role_name: str):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            user = session.get("user")
            if not user:
                return redirect(url_for("login"))
            if role_name == "admin" and user.get("role") != "admin":
                return "権限がありません（管理者専用）", 403
            return fn(*a, **kw)
        return wrapper
    return deco

def display_name_for(email: str, users: List[User]) -> str:
    mapping = {u.email: (u.name or u.email.split("@")[0]) for u in users}
    return mapping.get(email, (email.split("@")[0] if email else ""))

def parse_float(x) -> Optional[float]:
    if x is None or str(x).strip() == "":
        return None
    try:
        return float(str(x).replace(",", ""))
    except Exception:
        return None

def parse_dt(x) -> Optional[datetime]:
    if not x: return None
    try:
        return dtparse.parse(x)
    except Exception:
        return None

# ------------------ 認証 ------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email") or "").lower().strip()
        pw = request.form.get("password") or ""
        db = SessionLocal()
        try:
            u = db.query(User).filter(User.email == email).first()
            if u and u.verify(pw):
                session["user"] = {"email": u.email, "name": u.display_name(), "role": u.role}
                return redirect(request.args.get("next") or url_for("index"))
        finally:
            db.close()
        flash("メールまたはパスワードが違います", "error")
    return render_template_string(TPL_LOGIN)

@app.route("/logout")
@login_required
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

# 初期セットアップ（最初の管理者1人作成）
@app.route("/setup", methods=["GET", "POST"])
def setup():
    db = SessionLocal()
    try:
        if db.query(User).count() > 0:
            return redirect(url_for("login"))
        if request.method == "POST":
            User.create(db, request.form["email"], request.form["password"], request.form.get("name", ""), role="admin")
            return redirect(url_for("login"))
        return render_template_string(TPL_SETUP)
    finally:
        db.close()

# ------------------ 一覧（検索/並び替え） ------------------
@app.route("/")
@login_required
def index():
    q = (request.args.get("q") or "").strip()
    status = (request.args.get("status") or "")
    owner = (request.args.get("owner") or "")
    sort = request.args.get("sort") or "applied_at"
    desc_order = (request.args.get("desc", "1") == "1")
    start = parse_dt(request.args.get("start"))
    end = parse_dt(request.args.get("end"))

    db = SessionLocal()
    try:
        qs = db.query(Withdrawal)

        if q:
            like = f"%{q}%"
            qs = qs.filter(or_(
                Withdrawal.company.like(like),
                Withdrawal.no.like(like),
                Withdrawal.bank_name.like(like),
                Withdrawal.branch_name.like(like),
                Withdrawal.account_holder.like(like),
                Withdrawal.payout_account.like(like),
                Withdrawal.owner.like(like)
            ))
        if status:
            qs = qs.filter(Withdrawal.status == status)
        if owner:
            qs = qs.filter(Withdrawal.owner == owner)
        if start:
            qs = qs.filter(Withdrawal.applied_at >= start)
        if end:
            qs = qs.filter(Withdrawal.applied_at < end)

        sort_col = getattr(Withdrawal, sort, Withdrawal.applied_at)
        qs = qs.order_by(desc(sort_col) if desc_order else asc(sort_col))

        rows = qs.all()

        owners = [r[0] for r in db.query(Withdrawal.owner).distinct().all() if r[0]]
        stats = [r[0] for r in db.query(Withdrawal.status).distinct().all() if r[0]]

        # 今日の集計
        today0 = datetime.combine(date.today(), datetime.min.time())
        today1 = today0 + timedelta(days=1)
        t_q = db.query(func.count(Withdrawal.id), func.coalesce(func.sum(Withdrawal.amount), 0.0))\
            .filter(and_(Withdrawal.applied_at >= today0, Withdrawal.applied_at < today1)).one()
        today_count, today_amount = t_q[0] or 0, int(t_q[1] or 0)

        return render_template_string(
            TPL_INDEX,
            rows=rows, owners=owners, stats=stats,
            q=q, status=status, owner=owner, sort=sort, desc=desc_order,
            start=request.args.get("start") or "", end=request.args.get("end") or "",
            count=len(rows), user=session.get("user"),
            today_count=today_count, today_amount=today_amount
        )
    finally:
        db.close()

# ------------------ ステータス更新（完了/差し戻し） ------------------
@app.route("/toggle_status", methods=["POST"])
@login_required
def toggle_status():
    id_ = int(request.form["id"])
    next_ = request.form["next"]
    db = SessionLocal()
    try:
        obj = db.get(Withdrawal, id_)
        if not obj:
            return jsonify({"ok": False})
        obj.status = next_
        obj.last_changed_by = session["user"]["email"]
        obj.last_changed_at = datetime.utcnow()
        obj.updated_at = datetime.utcnow()
        db.add(obj)
        db.add(AuditLog(user_email=session["user"]["email"], action="status_update",
                        target=f"withdrawal:{id_}", detail=f"to={next_}"))
        db.commit()
        return jsonify({"ok": True, "status": next_})
    finally:
        db.close()

# ------------------ 一括削除（adminのみ・アーカイブ保存） ------------------
@app.route("/bulk_delete", methods=["POST"])
@login_required
@require_role("admin")
def bulk_delete():
    ids = request.form.get("ids", "")
    id_list = [int(x) for x in re.findall(r"\d+", ids)]
    if not id_list:
        return jsonify({"ok": False, "msg": "no ids"})
    db = SessionLocal()
    try:
        rows = db.query(Withdrawal).filter(Withdrawal.id.in_(id_list)).all()
        for r in rows:
            arc = ArchivedWithdrawal(
                original_id=r.id,
                company=r.company, no=r.no, applied_at=r.applied_at,
                bank_name=r.bank_name, branch_name=r.branch_name,
                account_type=r.account_type, account_number=r.account_number,
                account_holder=r.account_holder, amount=r.amount,
                payout_account=r.payout_account, fee=r.fee,
                status=r.status, owner=r.owner, memo=r.memo,
                created_at=r.created_at, updated_at=r.updated_at,
                last_changed_by=r.last_changed_by, last_changed_at=r.last_changed_at,
                deleted_at=datetime.utcnow(), deleted_by=session["user"]["email"]
            )
            db.add(arc)
            db.delete(r)
        db.add(AuditLog(user_email=session["user"]["email"], action="delete",
                        target=f"withdrawal:{len(id_list)}", detail=f"ids={id_list}"))
        db.commit()
        return jsonify({"ok": True, "deleted": len(id_list)})
    finally:
        db.close()

# ------------------ CSV I/O ------------------
@app.route("/upload", methods=["POST"])
@login_required
def upload():
    file = request.files["file"]
    text = file.stream.read().decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(text))
    db = SessionLocal()
    try:
        for row in reader:
            if all((not str(v or "").strip() for v in row.values())):
                continue
            # ヘッダ差異の吸収
            company = (row.get("会社") or row.get("クライアント") or "").strip()
            no_ = (row.get("No.") or row.get("No") or "").strip()

            obj = db.query(Withdrawal).filter(Withdrawal.no == no_).first() or Withdrawal(no=no_)
            obj.company = company
            obj.applied_at = parse_dt(row.get("申請日時"))
            obj.bank_name = (row.get("銀行名") or "").strip()
            obj.branch_name = (row.get("支店名") or "").strip()
            obj.account_type = (row.get("口座種別") or "").strip()
            obj.account_number = (row.get("口座番号") or "").strip()
            obj.account_holder = (row.get("口座名義") or "").strip()
            obj.amount = parse_float(row.get("金額"))
            obj.payout_account = (row.get("出金口座") or "").strip()
            obj.fee = parse_float(row.get("手数料"))
            obj.status = (row.get("ステータス") or "").strip()
            obj.owner = (row.get("担当者") or row.get("担当") or "").strip()
            obj.updated_at = datetime.utcnow()
            db.add(obj)

        db.add(AuditLog(user_email=session["user"]["email"], action="upload", target="csv"))
        db.commit()
    finally:
        db.close()
    return redirect(url_for("index"))

@app.route("/export")
@login_required
def export_csv():
    db = SessionLocal()
    try:
        rows = db.query(Withdrawal).order_by(Withdrawal.applied_at.desc()).all()
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["会社","No.","申請日時","銀行名","支店名","口座種別","口座番号","口座名義","金額","出金口座","手数料","ステータス","担当者"])
        for r in rows:
            writer.writerow([
                r.company or "", r.no or "",
                r.applied_at.strftime("%Y-%m-%d %H:%M:%S") if r.applied_at else "",
                r.bank_name or "", r.branch_name or "", r.account_type or "",
                r.account_number or "", r.account_holder or "",
                int(r.amount) if r.amount is not None else "",
                r.payout_account or "",
                int(r.fee) if r.fee is not None else "",
                r.status or "", r.owner or ""
            ])
        mem = io.BytesIO(output.getvalue().encode("utf-8-sig"))
        mem.seek(0)
        return send_file(mem, as_attachment=True, download_name="withdrawals.csv", mimetype="text/csv")
    finally:
        db.close()

# ------------------ ユーザー管理（adminのみ） ------------------
@app.route("/users")
@login_required
@require_role("admin")
def users_page():
    db = SessionLocal()
    try:
        users = db.query(User).order_by(User.created_at.desc()).all()
        return render_template_string(TPL_USERS, users=users, me=session["user"])
    finally:
        db.close()

@app.route("/users/create", methods=["POST"])
@login_required
@require_role("admin")
def users_create():
    email = request.form["email"].lower().strip()
    name = request.form.get("name","").strip()
    pw = request.form["password"]
    role = request.form.get("role","worker")
    db = SessionLocal()
    try:
        User.create(db, email=email, password=pw, name=name, role=role)
        db.add(AuditLog(user_email=session["user"]["email"], action="create_user", target=email))
        db.commit()
        return redirect(url_for("users_page"))
    finally:
        db.close()

@app.route("/users/role", methods=["POST"])
@login_required
@require_role("admin")
def users_role():
    id_ = int(request.form["id"])
    role = request.form["role"]
    db = SessionLocal()
    try:
        u = db.get(User, id_)
        if not u: return redirect(url_for("users_page"))
        u.role = role
        db.add(AuditLog(user_email=session["user"]["email"], action="role_change", target=u.email, detail=f"to={role}"))
        db.commit()
        return redirect(url_for("users_page"))
    finally:
        db.close()

@app.route("/users/resetpw", methods=["POST"])
@login_required
@require_role("admin")
def users_resetpw():
    id_ = int(request.form["id"])
    pw = request.form["password"]
    db = SessionLocal()
    try:
        u = db.get(User, id_)
        if not u: return redirect(url_for("users_page"))
        u.password_hash = generate_password_hash(pw)
        db.add(AuditLog(user_email=session["user"]["email"], action="reset_pw", target=u.email))
        db.commit()
        return redirect(url_for("users_page"))
    finally:
        db.close()

# ------------------ テンプレ ------------------
TPL_BASE = """
<!doctype html><html lang=ja><head>
<meta charset=utf-8><meta name=viewport content="width=device-width, initial-scale=1">
<title>出金管理</title>
<link rel="stylesheet" href="https://unpkg.com/@picocss/pico@2/css/pico.min.css">
<link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head><body><div class="wrap">
"""

# --- 追加：画面テンプレ ---

TPL_LOGIN = TPL_BASE + """
<h2>サインイン</h2>
{% with m = get_flashed_messages(with_categories=true) %}
  {% if m %}<div class="flash">
    {% for c,msg in m %}<p>{{ msg }}</p>{% endfor %}
  </div>{% endif %}
{% endwith %}
<form method="post" style="max-width:420px">
  <label>メール<input type="email" name="email" required></label>
  <label>パスワード<input type="password" name="password" required></label>
  <button class="btn" type="submit">ログイン</button>
  <p style="margin-top:8px">
    初回は <a href="{{ url_for('setup') }}">セットアップ</a> から管理者を登録してください
  </p>
</form>
</div></body></html>
"""

TPL_SETUP = TPL_BASE + """
<h2>初期セットアップ（管理者作成）</h2>
<form method="post" style="max-width:460px">
  <label>表示名<input name="name" placeholder="例: 管理太郎"></label>
  <label>メール<input type="email" name="email" required></label>
  <label>パスワード<input type="password" name="password" required></label>
  <button class="btn" type="submit">管理者を作成</button>
</form>
<p style="margin-top:8px"><a href="{{ url_for('login') }}">ログインへ戻る</a></p>
</div></body></html>
"""

TPL_INDEX = TPL_BASE + """
<div style="display:flex;justify-content:space-between;align-items:center;gap:12px;">
  <div>{{ user.name }}（{{ '管理者' if user.role=='admin' else '作業者' }}） / <a href="{{ url_for('logout') }}">ログアウト</a></div>
  <div style="display:flex;gap:8px;">
    {% if user.role == 'admin' %}
      <a class="btn secondary" href="{{ url_for('users_page') }}">ユーザー管理</a>
      <a class="btn secondary" href="{{ url_for('export_csv') }}">CSVエクスポート</a>
      <form id="csvForm" action="{{ url_for('upload') }}" method="post" enctype="multipart/form-data" style="display:inline;">
        <input type="file" name="file" accept=".csv" id="csvFile" hidden onchange="csvForm.submit()">
        <button type="button" class="btn secondary" onclick="csvFile.click()">CSVアップロード</button>
      </form>
    {% endif %}
  </div>
</div>

<div class="kpi">
  <div class="card"><div class="muted">今日の出金件数</div><div class="num">{{ today_count }}</div></div>
  <div class="card"><div class="muted">今日の出金金額</div><div class="num">{{ "{:,}".format(today_amount) }} 円</div></div>
</div>

<form method="get" class="toolbar-wrap">
  <div class="toolbar">
    <input type="search" name="q" placeholder="検索：会社/No./銀行/名義/出金口座/担当…" value="{{ q }}">
    <input type="date"  name="start" value="{{ start }}">
    <input type="date"  name="end"   value="{{ end }}">
    <select name="status">
      <option value="">ステータス: すべて</option>
      {% for s in stats %}<option value="{{s}}" {{'selected' if s==status else ''}}>{{s}}</option>{% endfor %}
    </select>
    <select name="owner">
      <option value="">担当者: すべて</option>
      {% for s in owners %}<option value="{{s}}" {{'selected' if s==owner else ''}}>{{s}}</option>{% endfor %}
    </select>
    <select name="sort">
      {% for key,label in [
        ('company','会社'),('no','No.'),('applied_at','申請日時'),
        ('bank_name','銀行名'),('branch_name','支店名'),('account_holder','口座名義'),
        ('amount','金額'),('payout_account','出金口座'),('status','ステータス'),('owner','担当者'),
      ] %}
      <option value="{{key}}" {{'selected' if sort==key else ''}}>{{label}}</option>
      {% endfor %}
    </select>
    <label style="display:flex;align-items:center;gap:6px;">
      <input type="checkbox" name="desc" value="1" {{'checked' if desc else ''}}> 降順
    </label>
    <button class="btn secondary" type="submit">検索</button>
  </div>
</form>

<div style="margin:6px 2px 10px;color:#6b7280">{{ count }} 件</div>

<form id="bulkForm" method="post" action="{{ url_for('bulk_delete') }}">
<div class="table-wrap"><table>
  <thead><tr>
    {% if user.role == 'admin' %}<th style="width:34px"><input type="checkbox" id="chkAll"></th>{% endif %}
    <th>会社</th><th>No.</th><th>申請日時</th><th>銀行名</th><th>支店名</th>
    <th>口座名義</th><th style="text-align:right;">金額</th><th>出金口座</th><th>ステータス</th><th>担当者</th><th>操作</th>
  </tr></thead>
  <tbody>
  {% for r in rows %}
    <tr class="{% if r.status=='完了' %}done{% elif r.status=='差し戻し' %}returned{% endif %}">
      {% if user.role == 'admin' %}
      <td><input type="checkbox" name="id" value="{{ r.id }}"></td>
      {% endif %}
      <td>{{ r.company or '' }}</td>
      <td>{{ r.no or '' }}</td>
      <td>{{ r.applied_at.strftime('%Y/%m/%d %H:%M') if r.applied_at else '' }}</td>
      <td>{{ r.bank_name or '' }}</td>
      <td>{{ r.branch_name or '' }}</td>
      <td>{{ r.account_holder or '' }}</td>
      <td class="money">{{ "{:,}".format(int(r.amount)) if r.amount is not none else '' }}</td>
      <td>{{ r.payout_account or '' }}</td>
      <td>
        {% if r.status=='完了' %}<span class="badge ok">完了</span>
        {% elif r.status=='差し戻し' %}<span class="badge hold">差し戻し</span>
        {% else %}<span class="badge">—</span>{% endif %}
      </td>
      <td>{{ r.owner or '' }}</td>
      <td>
        {% if r.status not in ['完了','差し戻し'] %}
          <div style="display:flex;gap:6px;">
            <button class="btn" data-id="{{r.id}}" data-next="完了" onclick="return toggleStatus(event,this)">完了</button>
            <button class="btn secondary warn" data-id="{{r.id}}" data-next="差し戻し" onclick="return toggleStatus(event,this)">差し戻し</button>
          </div>
        {% elif r.status=='完了' %}
          <span class="muted">完了済み</span>
        {% else %}
          <span class="muted">差し戻し済み</span>
        {% endif %}
      </td>
    </tr>
  {% endfor %}
  </tbody>
</table></div>

{% if user.role == 'admin' %}
  <div style="margin-top:12px">
    <button class="btn danger" type="button" onclick="bulkDelete()">選択行を一括削除（アーカイブへ）</button>
  </div>
{% endif %}
</form>

<script>
function toggleStatus(ev, btn){
  ev.preventDefault();
  const id = btn.dataset.id, next = btn.dataset.next;
  fetch('{{ url_for("toggle_status") }}', {
    method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:`id=${id}&next=${encodeURIComponent(next)}`
  }).then(r=>r.json()).then(d=>{
    if(d.ok){ location.reload(); } else { alert('更新失敗'); }
  });
  return false;
}
const chkAll = document.getElementById('chkAll');
if(chkAll){
  chkAll.addEventListener('change', ()=>{
    document.querySelectorAll('input[name="id"]').forEach(c=>c.checked = chkAll.checked);
  });
}
function bulkDelete(){
  const ids = [...document.querySelectorAll('input[name="id"]:checked')].map(x=>x.value);
  if(ids.length==0){ alert('行が選択されていません'); return; }
  if(!confirm(`選択 ${ids.length} 件を削除（アーカイブ保存）します。よろしいですか？`)) return;
  fetch('{{ url_for("bulk_delete") }}', {
    method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:`ids=${ids.join(',')}`
  }).then(r=>r.json()).then(d=>{
    if(d.ok){ location.reload(); } else { alert('削除失敗: '+(d.msg||'')); }
  });
}
</script>
</div></body></html>
"""

TPL_USERS = TPL_BASE + """
<h2>ユーザー管理</h2>
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
  <div>{{ me.name }}（{{ '管理者' if me.role=='admin' else '作業者' }}） / <a href="{{ url_for('logout') }}">ログアウト</a></div>
  <div style="display:flex;gap:8px;">
    <a class="btn secondary" href="{{ url_for('index') }}">&larr; 出金一覧へ</a>
  </div>
</div>

<div class="table-wrap" style="margin-bottom:18px;">
<table>
  <thead><tr>
    <th style="width:240px">メール</th>
    <th style="width:160px">表示名</th>
    <th style="width:140px">ロール</th>
    <th style="width:160px">作成日時</th>
    <th>操作</th>
  </tr></thead>
  <tbody>
    {% for u in users %}
    <tr>
      <td>{{ u.email }}</td>
      <td>{{ u.name or u.email.split('@')[0] }}</td>
      <td>
        <form method="post" action="{{ url_for('users_role') }}" style="display:flex;gap:8px;align-items:center">
          <input type="hidden" name="id" value="{{ u.id }}">
          <select name="role">
            <option value="admin"  {{ 'selected' if u.role=='admin' else '' }}>admin(管理者)</option>
            <option value="worker" {{ 'selected' if u.role!='admin' else '' }}>worker(作業者)</option>
          </select>
          <button class="btn secondary" style="height:32px;padding:0 10px;">変更</button>
        </form>
      </td>
      <td>{{ u.created_at.strftime('%Y/%m/%d %H:%M') if u.created_at else '' }}</td>
      <td>
        <form method="post" action="{{ url_for('users_resetpw') }}" style="display:flex;gap:8px;align-items:center">
          <input type="hidden" name="id" value="{{ u.id }}">
          <input type="password" name="password" placeholder="新パスワード" required style="height:32px">
          <button class="btn" style="height:32px;padding:0 12px;">PW再設定</button>
        </form>
      </td>
    </tr>
    {% endfor %}
  </tbody>
</table>
</div>

<h3>ユーザー追加</h3>
<form method="post" action="{{ url_for('users_create') }}" class="table-wrap" style="padding:12px;border-radius:12px;">
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

# ------------------ 起動 ------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
