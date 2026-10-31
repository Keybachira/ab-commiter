#!/usr/bin/env python3
"""smart-commit — analisa o que está em stage, gera a mensagem e sobe o commit.

Fluxo rápido:  smart-commit   ->  (stage) -> análise -> mensagem -> Enter -> commit + push

Com ANTHROPIC_API_KEY definida, a mensagem é escrita por IA a partir do diff.
Sem chave (ou sem rede), usa uma heurística local, que funciona offline.

Só usa a biblioteca padrão.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

MODELO_PADRAO = "claude-haiku-5-5"
LIMITE_DIFF = 12000          # caracteres do diff enviados à IA
LIMITE_FICHEIRO_MB = 5
LOCKFILES = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb",
             "uv.lock", "poetry.lock", "Cargo.lock"]
EXCLUIR_DA_IA = [f":(exclude,glob)**/{n}" for n in LOCKFILES] + [
    ":(exclude,glob)**/*.min.js", ":(exclude,glob)**/.env*",
    ":(exclude,glob)**/*.pem", ":(exclude,glob)**/*.key",
]

SEGREDOS = [
    ("chave AWS", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("chave Anthropic", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("chave sk-", re.compile(r"\bsk-[A-Za-z0-9]{32,}\b")),
    ("token GitHub", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}")),
    ("chave privada", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("credencial no código", re.compile(
        r"""(?i)\b(password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*['"][^'"\s]{8,}['"]""")),
]
CONFLITO = re.compile(r"^(<{7}|>{7})( |$)")
PASTAS_LIXO = re.compile(r"(^|/)(node_modules|dist|build|\.next|\.venv|__pycache__)/")
DEBUG_JS = re.compile(r"console\.log\(|\bdebugger\b")

# ---------- apresentação ----------


def _cor(cod, txt):
    return f"\033[{cod}m{txt}\033[0m" if sys.stdout.isatty() else txt


def verde(t): return _cor("32", t)
def amarelo(t): return _cor("33", t)
def vermelho(t): return _cor("31", t)
def cinza(t): return _cor("90", t)
def negrito(t): return _cor("1", t)


def preparar_consola():
    for s in (sys.stdout, sys.stderr, sys.stdin):
        try:
            s.reconfigure(encoding="utf-8")
        except Exception:
            pass
    if os.name == "nt":
        os.system("")  # activa cores ANSI no terminal do Windows


def confirmar(pergunta, padrao=True, auto=False):
    if auto:
        return True
    sufixo = "[S/n]" if padrao else "[s/N]"
    r = input(f"{pergunta} {sufixo} ").strip().lower()
    if not r:
        return padrao
    return r in ("s", "sim", "y", "yes")


# ---------- git ----------


def git(*args):
    return subprocess.run(
        ["git", "-c", "core.quotepath=off", *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )


def saida(*args):
    return git(*args).stdout.strip()


def ficheiros_staged():
    r = git("diff", "--cached", "--name-status")
    res = []
    for linha in r.stdout.splitlines():
        partes = linha.split("\t")
        if len(partes) >= 2:
            res.append((partes[0][0], partes[-1]))
    return res


def linhas_adicionadas():
    r = git("diff", "--cached", "-U0", "--no-color")
    ficheiro, res = None, []
    for l in r.stdout.splitlines():
        if l.startswith("+++ "):
            ficheiro = l[6:].rstrip("\t") if l.startswith("+++ b/") else None
        elif l.startswith("+") and ficheiro:
            res.append((ficheiro, l[1:]))
    return res


# ---------- análise ----------


def eh_lockfile(p):
    return Path(p).name in LOCKFILES


def nome_sensivel(p):
    n = Path(p).name
    if n.startswith(".env") and not n.endswith((".example", ".sample", ".template")):
        return True
    return n in ("id_rsa", "id_ed25519") or n.endswith((".pem", ".key", ".p12"))


def analisar(ficheiros, adicionadas, topo, ramo):
    bloqueios, avisos = [], []

    for s, p in ficheiros:
        if s != "D" and nome_sensivel(p):
            bloqueios.append(f"ficheiro sensível em stage: {p}")

    vistos = set()
    for f, l in adicionadas:
        if eh_lockfile(f):
            continue
        for nome, rx in SEGREDOS:
            if rx.search(l) and (f, nome) not in vistos:
                vistos.add((f, nome))
                bloqueios.append(f"possível {nome} em {f}")
        if CONFLITO.match(l) and (f, "conflito") not in vistos:
            vistos.add((f, "conflito"))
            bloqueios.append(f"marcador de conflito do git em {f}")

    lixo = [p for s, p in ficheiros if s != "D" and PASTAS_LIXO.search(p)]
    if lixo:
        avisos.append(f"{len(lixo)} ficheiro(s) de pastas geradas (node_modules/dist/build...) em stage, ex.: {lixo[0]}")

    for s, p in ficheiros:
        if s == "D":
            continue
        try:
            mb = os.path.getsize(os.path.join(topo, p)) / (1024 * 1024)
        except OSError:
            continue
        if mb > LIMITE_FICHEIRO_MB:
            avisos.append(f"ficheiro grande ({mb:.1f} MB): {p}")

    debug = sum(1 for f, l in adicionadas
                if f.endswith((".js", ".jsx", ".ts", ".tsx")) and DEBUG_JS.search(l))
    if debug:
        avisos.append(f"{debug} linha(s) com console.log/debugger adicionadas")

    areas = {a for a in (_area(p) for _, p in ficheiros) if a}
    if len(ficheiros) >= 8 and len(areas) >= 3:
        avisos.append(f"mudanças em {len(areas)} áreas ({', '.join(sorted(areas)[:4])}...) — talvez valha dividir em commits separados")

    if ramo in ("main", "master"):
        avisos.append(f"estás directamente na {ramo}")
    return bloqueios, avisos


def _area(p):
    seg = Path(p).parts
    if len(seg) < 2:
        return None
    if seg[0] in ("apps", "packages", "services") and len(seg) > 2:
        return seg[1]
    if seg[0] == "src" and len(seg) > 2:
        return seg[1]
    return seg[0]


# ---------- mensagem (heurística) ----------

EXT_DOC = {".md", ".mdx", ".txt", ".rst"}
EXT_ESTILO = {".css", ".scss", ".sass", ".less"}
NOMES_BUILD = {"package.json", "tsconfig.json", "pyproject.toml", "Dockerfile",
               "docker-compose.yml", "vite.config.ts", "next.config.js", "next.config.mjs",
               "tailwind.config.js", "tailwind.config.ts", ".gitignore", *LOCKFILES}

VERBOS = {
    "pt": {"feat": "adiciona", "fix": "corrige", "docs": "actualiza documentação de",
           "refactor": "refactoriza", "test": "actualiza testes de", "chore": "actualiza",
           "remove": "remove", "style": "ajusta estilos de", "build": "actualiza",
           "ci": "actualiza", "perf": "melhora desempenho de"},
    "en": {"feat": "add", "fix": "fix", "docs": "update docs for",
           "refactor": "refactor", "test": "update tests for", "chore": "update",
           "remove": "remove", "style": "adjust styles of", "build": "update",
           "ci": "update", "perf": "improve performance of"},
}


def classificar(ficheiros, ramo, texto_adicionado):
    m = re.match(r"(feat|fix|docs|refactor|test|chore|style|perf|build|ci)[/\-]", ramo)
    if m:
        return m.group(1)
    paths = [p for _, p in ficheiros]
    estados = Counter(s for s, _ in ficheiros)
    if estados["D"] == len(ficheiros):
        return "chore"
    if all(Path(p).name == ".gitignore" for p in paths):
        return "chore"
    if all(Path(p).suffix in EXT_DOC for p in paths):
        return "docs"
    if all(re.search(r"(^|/)(tests?|__tests__)/|\.(test|spec)\.", p) for p in paths):
        return "test"
    if all(p.startswith(".github/") for p in paths):
        return "ci"
    if all(Path(p).name in NOMES_BUILD for p in paths):
        return "build"
    if all(Path(p).suffix in EXT_ESTILO for p in paths):
        return "style"
    if estados["A"] >= max(1, len(ficheiros) / 2):
        return "feat"
    if re.search(r"\b(fix|bug|corrig\w*|erro|error|crash|null|undefined)\b", texto_adicionado, re.I):
        return "fix"
    return "refactor"


def detectar_escopo(paths):
    areas = [_area(p) for p in paths]
    unicos = set(areas)
    if len(unicos) == 1 and None not in unicos:
        return unicos.pop()
    return None


def juntar(nomes, lang):
    conj = "e" if lang == "pt" else "and"
    itens = nomes[:3]
    resto = len(nomes) - 3
    if resto > 0:
        itens.append(f"mais {resto}" if lang == "pt" else f"{resto} more")
    if len(itens) == 1:
        return itens[0]
    return ", ".join(itens[:-1]) + f" {conj} " + itens[-1]


def mensagem_heuristica(ficheiros, ramo, adicionadas, lang):
    paths = [p for _, p in ficheiros]
    texto = "\n".join(l for _, l in adicionadas)
    tipo = classificar(ficheiros, ramo, texto)
    escopo = detectar_escopo(paths)
    nomes = list(dict.fromkeys(Path(p).name if Path(p).name.startswith(".") else Path(p).stem for p in paths))
    assunto = f"{tipo}({escopo}): " if escopo else f"{tipo}: "
    chave = "remove" if all(s == "D" for s, _ in ficheiros) else tipo
    assunto += f"{VERBOS[lang][chave]} {juntar(nomes, lang)}"
    if len(assunto) > 72:
        assunto = assunto[:69].rstrip(", ") + "..."
    return assunto


# ---------- mensagem (IA) ----------


def mensagem_ia(chave, modelo, lang, ramo, stat, diff, recentes):
    idioma = "português europeu (Portugal/Angola, nunca brasileiro)" if lang == "pt" else "English"
    prompt = f"""Escreve a mensagem de commit para esta alteração.

Regras:
- Formato Conventional Commits: tipo(escopo opcional): descrição. Tipos: feat, fix, docs, style, refactor, perf, test, build, ci, chore.
- Primeira linha com no máximo 72 caracteres, sem ponto final.
- Língua da descrição: {idioma}. O tipo fica em inglês.
- Se a alteração for grande, deixa uma linha em branco e acrescenta até 4 linhas começadas por "- " a explicar o que mudou e porquê.
- Não inventes nada que não esteja no diff.
- Responde APENAS com a mensagem, sem aspas nem blocos de código.

Ramo: {ramo}
Commits recentes (para seguires o estilo):
{recentes or '(nenhum)'}

Resumo:
{stat}

Diff:
{diff}"""
    corpo = json.dumps({
        "model": modelo,
        "max_tokens": 400,
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages", data=corpo, method="POST",
        headers={"x-api-key": chave, "anthropic-version": "2023-06-01",
                 "content-type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=25) as r:
        dados = json.loads(r.read().decode("utf-8"))
    texto = "".join(b.get("text", "") for b in dados.get("content", []) if b.get("type") == "text")
    texto = re.sub(r"^```\w*\n?|\n?```$", "", texto.strip()).strip().strip('"')
    if not texto:
        raise ValueError("resposta vazia")
    return texto


def diff_para_ia():
    r = git("diff", "--cached", "-U2", "--no-color", "--", ".", *EXCLUIR_DA_IA)
    d = r.stdout
    if len(d) > LIMITE_DIFF:
        d = d[:LIMITE_DIFF] + "\n[... diff cortado ...]"
    return d


# ---------- commit e push ----------


def commitar(mensagem, editar):
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
        f.write(mensagem + "\n")
        caminho = f.name
    try:
        cmd = ["git", "commit", "-F", caminho]
        if editar:
            cmd.insert(2, "-e")
        return subprocess.run(cmd).returncode == 0
    finally:
        try:
            os.unlink(caminho)
        except OSError:
            pass


def subir(ramo):
    if ramo == "HEAD":
        print(amarelo("HEAD solto (detached): não faço push."))
        return True
    remotos = saida("remote").split()
    if not remotos:
        print(amarelo("Sem remote configurado: ficou só o commit local."))
        return True
    tem_up = git("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}").returncode == 0
    if tem_up:
        cmd = ["git", "push"]
    else:
        remoto = "origin" if "origin" in remotos else remotos[0]
        cmd = ["git", "push", "-u", remoto, "HEAD"]
    r = subprocess.run(cmd)
    if r.returncode != 0 and tem_up:
        if confirmar("Push rejeitado. Fazer 'git pull --rebase' e tentar de novo?", padrao=False):
            if subprocess.run(["git", "pull", "--rebase"]).returncode == 0:
                r = subprocess.run(["git", "push"])
            else:
                print(vermelho("Conflitos no rebase. Resolve-os, depois 'git rebase --continue' e 'git push'."))
    return r.returncode == 0


# ---------- .gitignore automático ----------


def _regra_dir(nome, untrack=True, extra=()):
    return {"nome": nome, "dirs": (nome,), "linhas": [nome + "/", *extra], "untrack": untrack}


# untrack=False: pode haver quem commite isto de propósito, por isso só se acrescenta ao
# .gitignore quando ainda não está no repositório, e nunca se remove do que já foi commitado.
REGRAS_IGNORE = [_regra_dir(n) for n in (
    "node_modules", ".next", ".nuxt", ".turbo", ".vercel", ".svelte-kit",
    ".parcel-cache", ".cache", ".pytest_cache", ".ruff_cache", ".mypy_cache",
    ".venv", "venv",
)] + [
    _regra_dir("dist", False),
    _regra_dir("build", False),
    _regra_dir("coverage", False),
    _regra_dir("__pycache__", True, ["*.py[cod]"]),
    {"nome": ".env", "linhas": [".env", ".env.*", "!.env.example"], "untrack": True,
     "ficheiro": lambda n: n.startswith(".env") and not n.endswith((".example", ".sample", ".template"))},
    {"nome": "logs", "linhas": ["*.log"], "untrack": True,
     "ficheiro": lambda n: n.endswith(".log")},
    {"nome": "sistema", "linhas": [".DS_Store", "Thumbs.db", "desktop.ini"], "untrack": True,
     "ficheiro": lambda n: n in (".DS_Store", "Thumbs.db", "desktop.ini")},
    {"nome": "chaves", "linhas": ["*.pem", "*.key"], "untrack": True,
     "ficheiro": lambda n: n.endswith((".pem", ".key"))},
    {"nome": "tsbuildinfo", "linhas": ["*.tsbuildinfo"], "untrack": True,
     "ficheiro": lambda n: n.endswith(".tsbuildinfo")},
]

BASE_IGNORE = [".env", ".env.*", "!.env.example", ".DS_Store", "Thumbs.db", "*.log"]
NODE_IGNORE = ["node_modules/", "dist/", ".next/", ".turbo/", ".vercel/", "coverage/", "*.tsbuildinfo"]
PY_IGNORE = ["__pycache__/", "*.py[cod]", ".venv/", "venv/", ".pytest_cache/", ".ruff_cache/"]
RUST_IGNORE = ["target/"]


def alvo_da_regra(regra, path):
    """Devolve o que deve ser ignorado/removido (pasta ou ficheiro) se o caminho bate na regra."""
    if "dirs" in regra:
        comps = path.split("/")
        for i, c in enumerate(comps):
            if c in regra["dirs"] and i < len(comps) - 1:
                return "/".join(comps[:i + 1])
        return None
    if path.endswith("/"):
        return None
    return path if regra["ficheiro"](path.split("/")[-1]) else None


def _lista_nul(*args):
    return [p for p in git(*args).stdout.split("\0") if p]


def desindexar(alvos):
    """Tira do git (mas não do disco)."""
    for i in range(0, len(alvos), 40):
        git("rm", "-r", "-f", "--cached", "--quiet", "--ignore-unmatch", "--", *alvos[i:i + 40])


def ajustar_gitignore(auto):
    """Garante que o que não deve subir fica no .gitignore e fora do stage.

    Corre ANTES do 'git add -A', para o node_modules nunca chegar a entrar.
    Devolve True se o .gitignore foi criado ou alterado.
    """
    caminho = Path(".gitignore")
    existente = caminho.read_text(encoding="utf-8", errors="replace") if caminho.exists() else None
    ja_tem = {l.strip() for l in (existente or "").splitlines()}
    novas = []

    def pedir(linhas):
        for l in linhas:
            if l not in ja_tem and l not in novas:
                novas.append(l)

    if existente is None:
        pedir(BASE_IGNORE)
        if Path("package.json").exists():
            pedir(NODE_IGNORE)
        if Path("pyproject.toml").exists() or Path("requirements.txt").exists():
            pedir(PY_IGNORE)
        if Path("Cargo.toml").exists():
            pedir(RUST_IGNORE)

    # 1) ficheiros novos que ainda não estão ignorados nem no git
    for p in _lista_nul("ls-files", "-o", "--exclude-standard", "--directory", "-z"):
        for r in REGRAS_IGNORE:
            if alvo_da_regra(r, p):
                pedir(r["linhas"])
                break

    # 2) ficheiros que já estão no índice do git mas não deviam
    novos_no_stage = {p for s, p in ficheiros_staged() if s == "A"}
    recentes, antigos = set(), set()
    for p in _lista_nul("ls-files", "-z"):
        for r in REGRAS_IGNORE:
            if not r["untrack"]:
                continue
            a = alvo_da_regra(r, p)
            if a:
                pedir(r["linhas"])
                (recentes if p in novos_no_stage else antigos).add(a)
                break
    recentes -= antigos

    alterou = False
    if novas:
        bloco = "\n".join(novas)
        if existente is None:
            texto = "# gerado pelo smart-commit\n" + bloco + "\n"
        else:
            sep = "" if (not existente or existente.endswith("\n")) else "\n"
            texto = existente + sep + "\n# adicionado pelo smart-commit\n" + bloco + "\n"
        caminho.write_text(texto, encoding="utf-8", newline="\n")
        alterou = True
        mostradas = ", ".join(novas[:6]) + (f" e mais {len(novas) - 6}" if len(novas) > 6 else "")
        estado = "criado" if existente is None else "actualizado"
        print(verde(f".gitignore {estado}: {mostradas}"))

    if recentes:
        desindexar(sorted(recentes))
        print(verde("Tirei do stage (continuam no disco): " + ", ".join(sorted(recentes)[:5])))

    if antigos:
        lista = sorted(antigos)
        print(amarelo("Já estão no repositório e não deviam: " + ", ".join(lista[:5])))
        if any(Path(a).name.startswith(".env") for a in lista):
            print(amarelo("  O .env já passou pelo histórico: troca as chaves que lá estão."))
        if not auto and confirmar("Remover do repositório (continuam no disco)?", True):
            desindexar(lista)
            print(verde("Removidos do repositório."))
        else:
            print(cinza("  para fazer depois: git rm -r --cached " + " ".join(lista[:3])))
    return alterou


# ---------- fluxo principal ----------


def mostrar_resumo(ficheiros, ramo):
    stat = saida("diff", "--cached", "--shortstat")
    print(f"{negrito('Ramo:')} {ramo}   {cinza(stat)}")
    cores = {"A": verde, "M": amarelo, "D": vermelho}
    for s, p in ficheiros[:12]:
        print(f"  {cores.get(s, cinza)(s)} {p}")
    if len(ficheiros) > 12:
        print(cinza(f"  ... e mais {len(ficheiros) - 12}"))


def main():
    preparar_consola()
    ap = argparse.ArgumentParser(prog="smart-commit",
                                 description="Analisa o stage, gera a mensagem e sobe o commit.")
    ap.add_argument("-a", "--tudo", action="store_true", help="faz 'git add -A' sem perguntar")
    ap.add_argument("-y", "--sim", action="store_true", help="não pergunta nada: commit e push logo")
    ap.add_argument("-n", "--sem-push", action="store_true", help="só commit, sem push")
    ap.add_argument("-m", "--mensagem", help="usa esta mensagem em vez de gerar uma")
    ap.add_argument("--sem-ia", action="store_true", help="usa só a heurística local")
    ap.add_argument("--sem-gitignore", action="store_true", help="não mexe no .gitignore")
    ap.add_argument("--en", action="store_true", help="mensagem em inglês")
    ap.add_argument("--dry", action="store_true", help="só mostra a análise e a mensagem")
    ap.add_argument("--forcar", action="store_true", help="continua mesmo com bloqueios (desliga a IA)")
    args = ap.parse_args()

    lang = "en" if args.en else os.environ.get("SMART_COMMIT_LANG", "pt")
    if lang not in VERBOS:
        lang = "pt"

    if git("rev-parse", "--is-inside-work-tree").returncode != 0:
        print(vermelho("Isto não é um repositório git."))
        return 1
    topo = saida("rev-parse", "--show-toplevel")
    os.chdir(topo)
    ramo = saida("symbolic-ref", "--short", "-q", "HEAD") or "HEAD"

    if not args.sem_gitignore:
        alterou = ajustar_gitignore(args.sim)
        if alterou and ficheiros_staged():
            git("add", "--", ".gitignore")

    ficheiros = ficheiros_staged()
    if not ficheiros:
        pendentes = saida("status", "--short")
        if not pendentes:
            print("Nada para commitar.")
            return 0
        print(pendentes)
        print()
        if args.tudo or confirmar("Nada em stage. Adicionar tudo (git add -A)?", True, args.sim):
            git("add", "-A")
            ficheiros = ficheiros_staged()
        else:
            print("Cancelado.")
            return 1
        if not ficheiros:
            print("Nada para commitar.")
            return 0

    adicionadas = linhas_adicionadas()
    mostrar_resumo(ficheiros, ramo)

    bloqueios, avisos = analisar(ficheiros, adicionadas, topo, ramo)
    for a in avisos:
        print(amarelo(f"  ! {a}"))
    usar_ia = not args.sem_ia
    if bloqueios:
        print()
        for b in bloqueios:
            print(vermelho(f"  x {b}"))
        if not args.forcar:
            print(vermelho("\nCommit bloqueado. Tira o que não deve subir (git restore --staged <ficheiro>)"))
            print(vermelho("ou usa --forcar se é um falso positivo."))
            return 1
        print(amarelo("  --forcar activo: a IA fica desligada para não enviar este conteúdo."))
        usar_ia = False
    print()

    chave = os.environ.get("ANTHROPIC_API_KEY")
    modelo = os.environ.get("SMART_COMMIT_MODEL", MODELO_PADRAO)
    stat = saida("diff", "--cached", "--stat")
    recentes = saida("log", "-5", "--pretty=%s") if git("rev-parse", "HEAD").returncode == 0 else ""

    def gerar():
        if usar_ia and chave:
            try:
                return mensagem_ia(chave, modelo, lang, ramo, stat, diff_para_ia(), recentes), "IA"
            except (urllib.error.URLError, urllib.error.HTTPError, ValueError, TimeoutError, OSError) as e:
                print(amarelo(f"IA indisponível ({type(e).__name__}); a usar heurística local."))
        return mensagem_heuristica(ficheiros, ramo, adicionadas, lang), "heurística"

    if args.mensagem:
        msg, origem = args.mensagem, "manual"
    else:
        msg, origem = gerar()

    print(f"{negrito('Mensagem')} {cinza('(' + origem + ')')}")
    for l in msg.splitlines():
        print(f"  {l}")
    print()

    if args.dry:
        return 0

    editar = False
    if not args.sim:
        acao = "commit" if args.sem_push else "commit + push"
        while True:
            r = input(f"[Enter] {acao}  |  e editar  |  r regenerar  |  n cancelar > ").strip().lower()
            if r == "":
                break
            if r == "e":
                editar = True
                break
            if r == "r":
                if origem == "IA":
                    msg, origem = gerar()
                    print(f"\n{negrito('Mensagem')} {cinza('(' + origem + ')')}")
                    for l in msg.splitlines():
                        print(f"  {l}")
                    print()
                else:
                    print("Sem IA não há alternativa; usa 'e' para editar.")
                continue
            if r in ("n", "q"):
                print("Cancelado.")
                return 1

    if not commitar(msg, editar):
        print(vermelho("Commit falhou ou foi cancelado (hooks? editor fechado sem guardar?)."))
        return 1

    curto = saida("rev-parse", "--short", "HEAD")
    print(verde(f"Commit {curto} criado."))

    if args.sem_push:
        return 0
    if subir(ramo):
        print(verde("Enviado."))
        return 0
    print(vermelho("Push falhou. O commit está guardado localmente."))
    return 1


def _entrada():
    try:
        return main()
    except KeyboardInterrupt:
        print("\nInterrompido.")
        return 130


if __name__ == "__main__":
    sys.exit(_entrada())
