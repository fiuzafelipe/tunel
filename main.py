from fastapi import FastAPI, Request, Form, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

import sqlite3, os, re, threading, time, base64, hmac, io
from datetime import datetime
from dateutil.relativedelta import relativedelta
from passlib.hash import bcrypt

app = FastAPI()

# ✅ GARANTE PASTAS
os.makedirs("static", exist_ok=True)
os.makedirs("templates", exist_ok=True)

templates = Jinja2Templates(directory="templates")

app.mount("/static", StaticFiles(directory="static"), name="static")

DB = "database.db"
LOG = "logs.txt"
LIC_DIR = "Licencas"

os.makedirs(LIC_DIR, exist_ok=True)

SECRET_KEY = os.getenv("SECRET_KEY", "DEFAULT_INSECURE_KEY").encode()

# ========================= HASH
def hash_senha(s):
    return bcrypt.hash(s)

def verify_senha(senha, hash_armazenado):
    try:
        return bcrypt.verify(senha, hash_armazenado)
    except:
        return False

# ========================= COOKIE
def criar_cookie(user):
    assinatura = hmac.new(SECRET_KEY, user.encode(), "sha256").hexdigest()
    return f"{user}|{assinatura}"

def validar_cookie(cookie):
    try:
        user, assinatura = cookie.split("|")
        esperado = hmac.new(SECRET_KEY, user.encode(), "sha256").hexdigest()
        return user if hmac.compare_digest(assinatura, esperado) else None
    except:
        return None

# ========================= DB
def get_conn():
    return sqlite3.connect(DB, check_same_thread=False)

# ========================= AUTH
def check_auth(auth):
    if not auth:
        return False

    user = validar_cookie(auth)
    if not user:
        return False

    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT 1 FROM usuarios WHERE user=?", (user,))
    ok = c.fetchone()
    conn.close()
    return user if ok else False

# ========================= DB INIT
def init_db():
    conn = get_conn()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        user TEXT PRIMARY KEY,
        senha TEXT,
        role TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS clientes (
        cnpj TEXT PRIMARY KEY,
        razao TEXT,
        validade TEXT,
        status TEXT,
        dia INTEGER,
        online TEXT DEFAULT 'OFFLINE'
    )
    """)

    user = "Felipe Fiuza"

    senha = "$2b$12$EqprvY0ApnwY/bbIINSsFe.9eXay7uxUK45Ylq767PtD2iFbG8YNO"

    c.execute("SELECT * FROM usuarios WHERE user=?", (user,))
    if not c.fetchone():
        c.execute("INSERT INTO usuarios VALUES (?,?,?)",
                  (user, senha, "admin"))

    conn.commit()
    conn.close()

init_db()

# ========================= UTILS
def formatar_cnpj(cnpj):
    cnpj = re.sub(r'\D', '', cnpj)
    if len(cnpj) != 14:
        return cnpj
    return f"{cnpj[:2]}.{cnpj[2:5]}.{cnpj[5:8]}/{cnpj[8:12]}-{cnpj[12:14]}"

def limpar_cnpj(cnpj):
    return re.sub(r'\D', '', cnpj)

def write_log(usuario, msg):
    data = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    if os.path.exists(LOG) and os.path.getsize(LOG) > 500000:
        os.remove(LOG)

    with open(LOG, "a", encoding="utf-8") as f:
        f.write(f"{data}|{usuario}|{msg}\n")

def read_logs():
    if not os.path.exists(LOG):
        return []
    with open(LOG, "r", encoding="utf-8") as f:
        return list(reversed([
            {"data":l.split("|")[0],
             "usuario":l.split("|")[1],
             "acao":l.split("|")[2].strip()}
            for l in f.readlines() if "|" in l
        ]))[:200]

def get_role(user):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT role FROM usuarios WHERE user=?", (user,))
    r = c.fetchone()
    conn.close()
    return r[0] if r else "cooperador"

# ========================= LOGIN
@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    msg = request.query_params.get("msg")

    return templates.TemplateResponse("login.html", {
        "request": request,
        "msg": msg
    })

@app.post("/login")
def login(user: str = Form(...), senha: str = Form(...)):
    conn = get_conn()
    c = conn.cursor()

    c.execute("SELECT senha FROM usuarios WHERE user=?", (user,))
    r = c.fetchone()
    conn.close()

    if r and verify_senha(senha, r[0]):
        cookie = criar_cookie(user)
        resp = RedirectResponse("/?msg=login_ok", 303)
        resp.set_cookie("auth", cookie, httponly=True, samesite="lax", secure=False)
        write_log(user, "Login")
        return resp

    return RedirectResponse("/login?msg=erro", 303)

@app.get("/logout")
def logout(auth: str = Cookie(None)):
    user = validar_cookie(auth) if auth else "Desconhecido"
    write_log(user, "Logout")
    resp = RedirectResponse("/login?msg=logout", 303)
    resp.delete_cookie("auth")
    return resp

# ========================= DASHBOARD
@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, auth: str = Cookie(None)):
    user = check_auth(auth)
    if not user:
        return RedirectResponse("/login")

    conn = get_conn()
    c = conn.cursor()

    c.execute("SELECT * FROM clientes")
    dados = c.fetchall()

    c.execute("SELECT * FROM usuarios")
    usuarios = c.fetchall()

    conn.close()

    clientes = []
    ativos = bloqueados = deletados = 0

    for d in dados:
        cnpj, razao, validade, status, dia, online = d
        clientes.append((formatar_cnpj(cnpj), razao, validade, status, cnpj, dia, online))

        if status == "ativo": ativos += 1
        elif status == "bloqueado": bloqueados += 1
        elif status == "deletado": deletados += 1

    msg = request.query_params.get("msg")

    return templates.TemplateResponse("index.html", {
        "request": request,
        "clientes": clientes,
        "usuarios": usuarios,
        "user": user,
        "role": get_role(user),
        "ativos": ativos,
        "bloqueados": bloqueados,
        "deletados": deletados,
        "logs": read_logs(),
        "msg": msg
    })

# ========================= CLIENTES
@app.post("/add_cliente")
def add_cliente(cnpj: str = Form(...), razao: str = Form(...), auth: str = Cookie(None)):
    user = check_auth(auth)
    if not user:
        return RedirectResponse("/login")

    conn = get_conn()
    c = conn.cursor()

    cnpj_limpo = limpar_cnpj(cnpj)

    c.execute("SELECT 1 FROM clientes WHERE cnpj=?", (cnpj_limpo,))
    if c.fetchone():
        conn.close()
        write_log(user, f"Tentativa CNPJ duplicado {cnpj}")
        return RedirectResponse("/?msg=cnpj_existente", 303)

    c.execute("SELECT 1 FROM clientes WHERE LOWER(razao)=LOWER(?)", (razao,))
    if c.fetchone():
        conn.close()
        write_log(user, f"Tentativa razão duplicada {razao}")
        return RedirectResponse("/?msg=razao_existente", 303)

    hoje = datetime.now()
    validade = hoje + relativedelta(months=1)

    c.execute("INSERT INTO clientes VALUES (?,?,?,?,?,?)",
              (cnpj_limpo, razao,
               validade.strftime("%d/%m/%Y"),
               "ativo", hoje.day, "OFFLINE"))

    conn.commit()
    conn.close()

    write_log(user, f"Cliente ativo {cnpj}")
    return RedirectResponse("/?msg=cliente_criado", 303)

# ========================= GERAR LICENÇA
@app.post("/gerar_chave")
def gerar_chave(cnpj: str = Form(...), auth: str = Cookie(None)):
    user = check_auth(auth)
    if not user:
        return RedirectResponse("/login")

    conn = get_conn()
    c = conn.cursor()

    c.execute("SELECT razao, validade FROM clientes WHERE cnpj=?", (cnpj,))
    r = c.fetchone()
    conn.close()

    if not r:
        return RedirectResponse("/", 303)

    razao, validade = r

    conteudo = f"{cnpj}|{razao}|{validade}"
    assinatura = hmac.new(SECRET_KEY, conteudo.encode(), "sha256").hexdigest()
    lic = base64.b64encode(f"{conteudo}|{assinatura}".encode()).decode()

    write_log(user, f"Gerou licença {cnpj}")

    response = StreamingResponse(io.BytesIO(lic.encode()), media_type="application/octet-stream")
    response.headers["Content-Disposition"] = f"attachment; filename={cnpj}.lic"
    return response

# ========================= RENOVAR
@app.post("/renovar_cliente")
def renovar(cnpj: str = Form(...), auth: str = Cookie(None)):
    user = check_auth(auth)
    if not user:
        return RedirectResponse("/login")

    conn = get_conn()
    c = conn.cursor()

    c.execute("SELECT validade FROM clientes WHERE cnpj=?", (cnpj,))
    r = c.fetchone()

    if r and r[0] != "-":
        nova = datetime.strptime(r[0], "%d/%m/%Y") + relativedelta(months=1)
    else:
        nova = datetime.now() + relativedelta(months=1)

    c.execute("UPDATE clientes SET validade=? WHERE cnpj=?",
              (nova.strftime("%d/%m/%Y"), cnpj))

    conn.commit()
    conn.close()

    write_log(user, f"Renovado {cnpj}")
    return RedirectResponse("/?msg=cliente_renovado", 303)

# ========================= STATUS
@app.post("/update_status")
def update_status(cnpj: str = Form(...), status: str = Form(...), dia: int = Form(1), auth: str = Cookie(None)):
    user = check_auth(auth)
    if not user:
        return RedirectResponse("/login")

    conn = get_conn()
    c = conn.cursor()

    if status == "ativo":
        hoje = datetime.now()
        validade = datetime(hoje.year, hoje.month, dia)
        if validade < hoje:
            validade += relativedelta(months=1)

        c.execute("UPDATE clientes SET status=?, validade=?, dia=? WHERE cnpj=?",
                  ("ativo", validade.strftime("%d/%m/%Y"), dia, cnpj))

    elif status == "bloqueado":
        c.execute("UPDATE clientes SET status=? WHERE cnpj=?",
                  ("bloqueado", cnpj))

    elif status == "deletado":
        c.execute("UPDATE clientes SET status=?, validade='-' WHERE cnpj=?",
                  ("deletado", cnpj))

    conn.commit()
    conn.close()

    write_log(user, f"{status} {cnpj}")
    return RedirectResponse(f"/?msg=cliente_{status}", 303)

# ========================= KILL
@app.post("/kill_cliente")
def kill(cnpj: str = Form(...), auth: str = Cookie(None)):
    user = check_auth(auth)
    if not user:
        return RedirectResponse("/login")

    conn = get_conn()
    c = conn.cursor()

    c.execute("UPDATE clientes SET online='DESCONECTADO' WHERE cnpj=?", (cnpj,))
    conn.commit()
    conn.close()

    def voltar():
        time.sleep(10)
        conn = get_conn()
        c = conn.cursor()
        c.execute("UPDATE clientes SET online='OFFLINE' WHERE cnpj=?", (cnpj,))
        conn.commit()
        conn.close()

    threading.Thread(target=voltar, daemon=True).start()

    write_log(user, f"Kill {cnpj}")
    return RedirectResponse("/?msg=cliente_kill", 303)

# ========================= REMOVER CLIENTE
@app.post("/remover_cliente")
def remover_cliente(cnpj: str = Form(...), auth: str = Cookie(None)):
    user = check_auth(auth)
    if not user:
        return RedirectResponse("/login")

    conn = get_conn()
    c = conn.cursor()

    c.execute("DELETE FROM clientes WHERE cnpj=?", (cnpj,))
    conn.commit()
    conn.close()

    write_log(user, f"Removido {cnpj}")
    return RedirectResponse("/?msg=cliente_removido", 303)

# ========================= USUÁRIOS
@app.post("/criar_usuario")
def criar_usuario(user: str = Form(...), senha: str = Form(...), role: str = Form(...), auth: str = Cookie(None)):
    user_auth = check_auth(auth)
    if get_role(user_auth) != "admin":
        return RedirectResponse("/", 303)

    conn = get_conn()
    c = conn.cursor()

    c.execute("SELECT * FROM usuarios WHERE user=?", (user,))
    if c.fetchone():
        conn.close()
        return RedirectResponse("/?msg=usuario_existente", 303)

    c.execute("INSERT INTO usuarios VALUES (?,?,?)",
              (user, hash_senha(senha), role))

    conn.commit()
    conn.close()

    write_log(user_auth, f"Criou usuário {user}")
    return RedirectResponse("/?msg=usuario_criado", 303)
