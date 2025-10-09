# app.py — 出金管理（ユーザー名ログイン版・フル機能）
# ----------------------------------------------------------
# - ログイン/ログアウト（admin / worker）※ユーザー名でログイン
# - 初期セットアップ（最初の管理者作成）
# - ユーザー管理（adminのみ：追加/ロール変更/パス再設定）
# - CSV アップロード / エクスポート（UTF-8 BOM対応）
# - 検索・絞り込み・日付範囲・並び替え
# - ワンクリック「完了 / 差し戻し」
# - 操作ログ（誰がいつ何を）
# - 管理者のみ：一括削除（削除はアーカイブに移動）
# - 会社列（旧クライアント）・操作カラムはタイムスタンプ/ユーザー名

from __future__ import annotations
import io, csv, os, re
from datetime import datetime, date, timedelta
from dateutil import parser as dtparse
from functools import wraps
from typing import Optional, List

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

# ================== 設定 ==================
DB_URL = os.environ.get("DATABASE_URL", "sqlite:///data.sqlite3")
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret")

engine = create_engine(
    DB_URL,
    connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {}
)
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine)

# ================== モデル ==================
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True, nullable=False)  # ← ユーザー名でログイン
    name = Column(String(100))                                   # 表示名
    role = Column(String(20), default="worker")                  # 'admin' or 'worker'
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    @staticmethod
    def create(session, username: str, password: str, name: str = "", role: str = "worker"):
        u = User(
            username=username.strip(),
            name=(name or "").strip(),
            role=role,
            password_hash=generate_password_hash(password),
        )
        session.add(u)
        session.commit()
        return u

    def verify(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def display_name(self) -> str:
        return self.name or self.username


class Withdrawal(Base):
    __tablename__ = "withdrawals"
    id = Column(Integer, primary_key=True)
    company = Column(String(64))            # 会社（旧クライアント）
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
    last_changed_by = Column(String(255))   # 直近の更新者（username）
    last_changed_at = Column(DateTime)


class ArchivedWithdrawal(Base):
    """削除時にここへフルコピー（監査保存）"""
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
    deleted_by = Column(String(255))        # 削除実施者（username）


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, default=datetime.utcnow)
    username = Column(String(255))          # 実施者（username）
    action = Column(String(64))             # 'status_update','upload','delete','create_user','reset_pw','role_change'
    target = Column(String(64))             # 'withdrawal:123', etc.
    detail = Column(Text)


Base.metadata.create_all(engine)

# ================== Flask ==================
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.jinja_env.globals['int'] = int  # jinja2 で int を使えるように

# ================== ヘルパ ==================
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

def parse_float(x) -> Optional[float]:
    if x is None or str(x).strip() == "":
        return None
    try:
        return float(str(x).replace(",", ""))
    except Exception:
        return None

def parse_dt(x) -> Optional[datetime]:
    if not x:
        return None
    try:
        return dtparse.parse(x)
    except Exception:
        return None

# ================== 認証 ==================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        pw = request.form.get("password") or ""
        db = SessionLocal()
        try:
            u = db.query(User).filter(User.username == username).first()
            if u and u.verify(pw):
                session["user"] = {"username": u.username, "name": u.display_name(), "role": u.role}
                return redirect(request.args.get("next") or url_for("index"))
        finally:
            db.close()
        flash("ユーザー名またはパスワードが違います", "error")
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
            User.create(
                db,
                username=request.form["username"],
                password=request.form["password"],
                name=request.form.get("name", ""),
                role="admin",
            )
            return redirect(url_for("login"))
        return render_template_string(TPL_SETUP)
    finally:
        db.close()

# ================== 一覧（検索/並び替え） ==================
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
                Withdrawal.owner.like(like),
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
        t_q = db.query(func.count(Withdrawal.id), func.coalesce(func.sum(Withdrawal.amount), 0.0)) \
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

# ================== ステータス更新 ==================
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
        obj.last_changed_by = session["user"]["username"]
        obj.last_changed_at = datetime.utcnow()
        obj.updated_at = datetime.utcnow()
        db.add(obj)
        db.add(AuditLog(username=session["user"]["username"], action="status_update",
                        target=f"withdrawal:{id_}", detail=f"to={next_}"))
        db.commit()
        return jsonify({"ok": True, "status": next_})
    finally:
        db.close()

# ================== 一括削除（adminのみ・アーカイブ保存） ==================
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
                deleted_at=datetime.utcnow(), deleted_by=session["user"]["username"]
            )
            db.add(arc)
            db.delete(r)
        db.add(AuditLog(username=session["user"]["username"], action="delete",
                        target=f"withdrawal:{len(id_list)}", detail=f"ids={id_list}"))
        db.commit()
        return jsonify({"ok": True, "deleted": len(id_list)})
    finally:
        db.close()

# ================== CSV I/O ==================
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

        db.add(AuditLog(username=session["user"]["username"], action="upload", target="csv"))
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

# ================== ユーザー管理（adminのみ） ==================
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
    username = request.form["username"].strip()
    name = request.form.get("name", "").strip()
    pw = request.form["password"]
    role = request.form.get("role", "worker")
    db = SessionLocal()
    try:
        User.create(db, username=username, password=pw, name=name, role=role)
        db.add(AuditLog(username=session["user"]["username"], action="create_user", target=username))
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
        if not u:
            return redirect(url_for("users_page"))
        u.role = role
        db.add(AuditLog(username=session["user"]["username"], action="role_change", target=u.username, detail=f"to={role}"))
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
        if not u:
            return redirect(url_for("users_page"))
        u.password_hash = generate_password_hash(pw)
        db.add(AuditLog(username=session["user"]["username"], action="reset_pw", target=u.username))
        db.commit()
        return redirect(url_for("users_page"))
    finally:
        db.close()

# ================== テンプレ ==================
TPL_BASE = """
<!doctype html><html lang=ja><head>
<meta charset=utf-8><meta name=viewport content="width=device-width, initial-scale=1">
<title>出金管理</title>
<link rel="stylesheet" href="{{ url_for('static', filename='vendor/pico.min.css') }}?v=1">
<link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}?v=6">
</head><body><div class="wrap">
"""

TPL_LOGIN = TPL_BASE + """
<h2>ログイン</h2>
<form method="post" style="max-width:420px">
  <label>ユーザー名<input type="text" name="username" required></label>
  <label>パスワード<input type="password" name="password" required></label>
  <button class="btn" type="submit">ログイン</button>
  <p><a href="/setup">初期セットアップ</a>（初回のみ）</p>
</form>
</div></body></html>
"""

TPL_SETUP = TPL_BASE + """
<h2>初期セットアップ（管理者作成）</h2>
<form method="post" style="max-width:460px">
  <label>表示名<input name="name" placeholder="例: 管理太郎"></label>
  <label>ユーザー名<input name="username" required placeholder="admin"></label>
  <label>パスワード<input type="password" name="password" required></label>
  <button class="btn" type="submit">管理者を作成</button>
</form>
</div></body></html>
"""

# 見た目は既存の style.css を利用（ボタン下線なし・整列済み前提）
TPL_INDEX = TPL_BASE + """
<h2>出金一覧</h2>
<div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap">
  <div>{{ user.name }}（{{ '管理者' if user.role=='admin' else '作業者' }}） / <a href="/logout">ログアウト</a></div>
  <div style="display:flex;gap:10px;align-items:center">
    {% if user.role=='admin' %}
      <a class="btn secondary" href="/users">ユーザー管理</a>
      <a class="btn secondary" href="/export">CSVエクスポート</a>
      <form id="csvForm" action="/upload" method="post" enctype="multipart/form-data" style="display:inline;">
        <input type="file" name="file" accept=".csv" id="csvFile" hidden onchange="csvForm.submit()">
        <button type="button" class="btn secondary" onclick="csvFile.click()">CSVアップロード</button>
      </form>
    {% endif %}
  </div>
</div>

<div style="margin:10px 0;display:flex;gap:20px;flex-wrap:wrap">
  <div>今日の出金件数: <b>{{today_count}}</b></div>
  <div>今日の出金金額: <b>{{"{:,}".format(today_amount)}}</b>円</div>
</div>

<form method="get" class="table-wrap" style="padding:10px;margin-bottom:10px">
  <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
    <input name="q" value="{{ q }}" placeholder="検索：会社/No./銀行/名義/出金/担当" style="min-width:260px">
    <input name="start" value="{{ start }}" placeholder="開始日(例:2025-10-01)">
    <input name="end" value="{{ end }}" placeholder="終了日(例:2025-10-31)">
    <select name="status">
      <option value="">ステータス</option>
      {% for s in stats %}<option value="{{s}}" {{'selected' if s==status else ''}}>{{s}}</option>{% endfor %}
    </select>
    <select name="owner">
      <option value="">担当者</option>
      {% for o in owners %}<option value="{{o}}" {{'selected' if o==owner else ''}}>{{o}}</option>{% endfor %}
    </select>
    <select name="sort">
      <option value="applied_at" {{'selected' if sort=='applied_at' else ''}}>申請日時</option>
      <option value="company" {{'selected' if sort=='company' else ''}}>会社</option>
      <option value="amount" {{'selected' if sort=='amount' else ''}}>金額</option>
      <option value="status" {{'selected' if sort=='status' else ''}}>ステータス</option>
    </select>
    <label><input type="checkbox" name="desc" value="1" {{'checked' if desc else ''}}> 降順</label>
    <button class="btn" type="submit">検索</button>
  </div>
</form>

<form id="bulkForm" method="post" action="/bulk_delete">
<div class="table-wrap"><table>
  <thead><tr>
    <th>会社</th><th>No.</th><th>申請日時</th><th>銀行名</th><th>支店名</th>
    <th>口座名義</th><th>金額</th><th>出金口座</th><th>ステータス</th><th>担当者</th><th>操作</th>
  </tr></thead>
  <tbody>
  {% for r in rows %}
  <tr data-id="{{r.id}}" class="{% if r.status=='完了' %}done{% elif r.status=='差し戻し' %}returned{% endif %}">
    <td>{{r.company or ''}}</td>
    <td>{{r.no or ''}}</td>
    <td>{{r.applied_at.strftime('%Y/%m/%d %H:%M') if r.applied_at else ''}}</td>
    <td>{{r.bank_name or ''}}</td>
    <td>{{r.branch_name or ''}}</td>
    <td>{{r.account_holder or ''}}</td>
    <td style="text-align:right">{{ "{:,}".format(int(r.amount)) if r.amount is not none else '' }}</td>
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
          <button class="btn" type="button" onclick="toggleStatus({{r.id}}, '完了', this)">完了</button>
          <button class="btn secondary" type="button" style="border-color:#cfa900;color:#cfa900;" onclick="toggleStatus({{r.id}}, '差し戻し', this)">差し戻し</button>
        </div>
      {% elif r.status=='完了' %}
        <span style="color:#6b7280;font-size:12px;">完了済み（{{r.last_changed_by}} / {{ r.last_changed_at.strftime('%Y-%m-%d %H:%M') if r.last_changed_at else ''}}）</span>
      {% elif r.status=='差し戻し' %}
        <span style="color:#8a5200;font-size:12px;">差し戻し済み（{{r.last_changed_by}} / {{ r.last_changed_at.strftime('%Y-%m-%d %H:%M') if r.last_changed_at else ''}}）</span>
      {% endif %}
      {% if user.role=='admin' %}
        <label style="margin-left:10px"><input type="checkbox" name="ids" value="{{r.id}}"> 選択</label>
      {% endif %}
    </td>
  </tr>
  {% endfor %}
  </tbody>
</table></div>

{% if user.role=='admin' %}
  <button class="btn" type="button" onclick="bulkDelete()">選択行を一括削除（アーカイブへ）</button>
{% endif %}
</form>

<script>
function toggleStatus(id, next, btn){
  fetch('/toggle_status',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:`id=${id}&next=${next}`})
  .then(r=>r.json()).then(data=>{
    if(data.ok){
      const tr = btn.closest('tr');
      const td = tr.querySelector('td:nth-child(9)');
      td.innerHTML = (next==='完了') ? '<span class="badge ok">完了</span>' : '<span class="badge hold">差し戻し</span>';
      tr.classList.remove('done','returned');
      if(next==='完了'){ tr.classList.add('done'); }
      if(next==='差し戻し'){ tr.classList.add('returned'); }
      const op = tr.querySelector('td:nth-child(11) div');
      if(op){ op.outerHTML = (next==='完了')
          ? '<span style="color:#6b7280;font-size:12px;">完了済み</span>'
          : '<span style="color:#8a5200;font-size:12px;">差し戻し済み</span>'; }
    } else alert('更新失敗');
  });
}

function bulkDelete(){
  const ids=[...document.querySelectorAll('input[name=ids]:checked')].map(x=>x.value);
  if(ids.length===0){ alert('削除する行を選択してください'); return; }
  if(!confirm(ids.length+'件を削除(アーカイブ)します。よろしいですか？')) return;
  const body='ids='+encodeURIComponent(ids.join(','));
  fetch('/bulk_delete',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body})
    .then(r=>r.json()).then(d=>{ if(d.ok){ location.reload(); } else { alert('削除失敗: '+(d.msg||'')); } });
}
</script>

</div></body></html>
"""

TPL_USERS = TPL_BASE + """
<h2>ユーザー管理</h2>

<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
  <div><a href="/" class="btn secondary">&larr; 出金一覧へ</a></div>
  <div style="color:#64748b">
    {{ me.name }}（{{ '管理者' if me.role=='admin' else '作業者' }}）
  </div>
</div>

<div class="table-wrap" style="margin-bottom:18px;">
<table>
  <thead><tr>
    <th style="width:200px">ユーザー名</th>
    <th style="width:160px">表示名</th>
    <th style="width:140px">ロール</th>
    <th style="width:160px">作成</th>
    <th>操作</th>
  </tr></thead>
  <tbody>
    {% for u in users %}
    <tr>
      <td>{{ u.username }}</td>
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
    <label>ユーザー名<input type="text" name="username" required></label>
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

# ================== 起動 ==================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)

