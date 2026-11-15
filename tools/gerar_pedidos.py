"""Gera os arquivos da página "Meus pedidos" (pedidos/d/) a partir do Pedidos Sírius.

Uso: python3 tools/gerar_pedidos.py PASTA_DO_BANCO
  PASTA_DO_BANCO tem as subpastas clientes/ e pedidos/ com um JSON por documento
  (como o ArtifactData salva com out_dir).

Cada cliente com pedido vira um arquivo pedidos/d/<id>.json. O id e a chave saem só do
CPF/CNPJ (PBKDF2-SHA256, 200 mil voltas) e o conteúdo vai cifrado (AES-GCM), igual à página.
Só entram clientes cadastrados com CPF/CNPJ; pedidos de exemplo ficam de fora.
"""
import sys, os, json, glob, base64, hashlib, re
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE = sys.argv[1]
SAIDA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "pedidos", "d")
BR = timezone(timedelta(hours=-3))
SIT = {"Aguardando fechamento do pedido": "aguardando_fechamento", "Aguardando pagamento": "aguardando_pagamento", "Em aberto": "aguardando_pagamento",
       "Pago": "em_separacao", "Separando": "em_separacao", "Em separação": "em_separacao",
       "Enviado para transportadora": "enviado_transportadora", "Enviado": "enviado_transportadora",
       "Cancelado": "cancelado"}

def ler(sub):
    out = {}
    for f in glob.glob(os.path.join(BASE, sub, "*.json")):
        d = json.load(open(f)); out[os.path.basename(f)[:-5]] = d.get("data", d)
    return out

def norm(t):
    import unicodedata
    t = unicodedata.normalize("NFD", str(t or "")).encode("ascii", "ignore").decode().lower()
    return re.sub(r"\s+", " ", t).strip()

def dk(seg, sal, n):
    return hashlib.pbkdf2_hmac("sha256", seg.encode(), sal.encode(), 200000, n)

def dia(iso):
    try: return datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone(BR)
    except Exception: return None

clientes, pedidos = ler("clientes"), ler("pedidos")
def dono(p):
    if p.get("clienteId") in clientes: return p["clienteId"]
    k, tel = norm(p.get("cliente")), re.sub(r"\D", "", p.get("telefone") or "")
    for cid, c in clientes.items():
        if k and k in [norm(c.get(x)) for x in ("fantasia", "razao", "nome", "completo") if c.get(x)]: return cid
        if len(tel) >= 10 and re.sub(r"\D", "", c.get("telefone") or "") == tel: return cid
    return None

grupos, sem = {}, 0
for pid, p in pedidos.items():
    if "exemplo" in norm(p.get("cliente")) or not p.get("itens"): continue
    cid = dono(p); doc = re.sub(r"\D", "", (clientes.get(cid) or {}).get("cnpj") or "")
    if len(doc) not in (11, 14): sem += 1; continue
    grupos.setdefault(doc, (cid, []))[1].append(p)

os.makedirs(SAIDA, exist_ok=True)
for f in glob.glob(os.path.join(SAIDA, "*.json")): os.remove(f)
agora = datetime.now(BR)
for doc, (cid, ps) in grupos.items():
    c = clientes[cid]; lista = []
    for p in ps:
        ini = dia(p.get("finalizadoEm") or p.get("criadoEm")); st = SIT.get(p.get("status"), "aguardando_pagamento")
        item = {"n": p.get("numero"), "data": ini.strftime("%Y-%m-%d") if ini else "", "status": st}
        if st not in ("enviado_transportadora", "cancelado", "aguardando_fechamento") and ini: item["previsao"] = (ini + timedelta(hours=48)).strftime("%Y-%m-%d")
        if p.get("nf"): item["nf"] = re.sub(r"\D", "", p["nf"])
        lista.append(item)
    dados = {"cliente": c.get("fantasia") or c.get("razao") or c.get("nome") or "", "pedidos": lista, "atualizado": agora.strftime("%Y-%m-%d")}
    iv = os.urandom(12)
    cif = AESGCM(dk(doc, "sirius-pedidos-key", 32)).encrypt(iv, json.dumps(dados, ensure_ascii=False).encode(), None)
    nome = dk(doc, "sirius-pedidos-id", 16).hex()
    json.dump({"iv": base64.b64encode(iv).decode(), "d": base64.b64encode(cif).decode()}, open(os.path.join(SAIDA, nome + ".json"), "w"))
print(f"{len(grupos)} cliente(s) publicados; {sem} pedido(s) sem cliente com CPF/CNPJ ficaram de fora")
