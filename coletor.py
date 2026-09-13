"""
Módulo 1 — Coletor de Logs (SecuraPy SIEM)
Lê os arquivos de log e normaliza cada linha em um evento (dict) padronizado.
"""

import os


def parsear_linha_auth(linha):
    """Parseia uma linha do auth.log e retorna dict normalizado."""
    linha = linha.strip()
    partes = linha.split()
    # partes = ['2025-02-20', '08:15:01', 'FAIL', 'usuario=admin', 'ip=185.220.101.1']

    data = partes[0]
    hora = partes[1]
    tipo = partes[2]
    usuario = partes[3].split("=")[1]
    ip = partes[4].split("=")[1]

    evento = {
        "timestamp": f"{data} {hora}",
        "fonte": "auth",
        "tipo": tipo,
        "ip": ip,
        "detalhes": f"usuario={usuario}",
        "linha_original": linha,
    }
    return evento


def parsear_linha_firewall(linha):
    """Parseia uma linha do firewall.log e retorna dict normalizado."""
    linha = linha.strip()
    partes = linha.split()
    # partes = ['2025-02-20', '08:10:02', 'BLOCK', 'proto=TCP', 'src=185.220.101.1', 'dst=10.0.0.1', 'dport=22']

    data = partes[0]
    hora = partes[1]
    tipo = partes[2]
    proto = partes[3].split("=")[1]
    src = partes[4].split("=")[1]
    dst = partes[5].split("=")[1]
    dport = partes[6].split("=")[1]

    evento = {
        "timestamp": f"{data} {hora}",
        "fonte": "firewall",
        "tipo": tipo,
        "ip": src,  # o IP de origem é o suspeito, é ele que interessa pro resto do sistema
        "detalhes": f"proto={proto} dst={dst} dport={dport}",
        "linha_original": linha,
    }
    return evento


def parsear_linha_web(linha):
    """Parseia uma linha do web_access.log e retorna dict normalizado."""
    linha = linha.strip()
    partes = linha.split()
    # partes = ['2025-02-20', '08:20:15', 'GET', 'url=/search?q=<script>alert(1)</script>', 'ip=45.33.32.156', 'status=400']

    data = partes[0]
    hora = partes[1]
    metodo = partes[2]
    # split("=", 1): quebra só no PRIMEIRO "=", pra não estragar URLs que já têm "=" dentro (ex: ?q=...)
    url = partes[3].split("=", 1)[1]
    ip = partes[4].split("=")[1]
    status = partes[5].split("=")[1]

    evento = {
        "timestamp": f"{data} {hora}",
        "fonte": "web",
        "tipo": metodo,
        "ip": ip,
        "detalhes": f"url={url} status={status}",
        "linha_original": linha,
    }
    return evento


# Cada fonte usa um parser diferente — esse dict funciona como uma "tabela de escolha"
PARSERS_POR_FONTE = {
    "auth": parsear_linha_auth,
    "firewall": parsear_linha_firewall,
    "web": parsear_linha_web,
}


def carregar_log(caminho_arquivo, fonte):
    """
    Lê um arquivo de log e retorna lista de eventos normalizados.
    - caminho_arquivo: str com o path do arquivo
    - fonte: str indicando o tipo ("auth", "firewall", "web")
    - Retorna: list[dict] com os eventos parseados
    """
    eventos = []
    parser = PARSERS_POR_FONTE.get(fonte)

    if parser is None:
        print(f"[ERRO] Fonte desconhecida: {fonte}")
        return eventos

    try:
        with open(caminho_arquivo, "r") as arquivo:
            for numero_linha, linha in enumerate(arquivo, start=1):
                linha = linha.strip()
                if not linha:
                    continue  # ignora linhas em branco silenciosamente

                try:
                    evento = parser(linha)
                    eventos.append(evento)
                except (IndexError, ValueError):
                    # linha mal formatada: avisa e segue pra próxima, sem travar o programa
                    print(f"[AVISO] Linha {numero_linha} ignorada (formato inválido) em {caminho_arquivo}: {linha}")
                    continue

    except FileNotFoundError:
        print(f"[ERRO] Arquivo não encontrado: {caminho_arquivo}")
        return []

    if not eventos:
        print(f"[INFO] Nenhum evento carregado de {caminho_arquivo} (arquivo vazio ou só com linhas inválidas)")

    return eventos


def _identificar_fonte_pelo_nome(nome_arquivo):
    """Descobre a fonte (auth/firewall/web) a partir do nome do arquivo."""
    nome = nome_arquivo.lower()
    if "auth" in nome:
        return "auth"
    if "firewall" in nome:
        return "firewall"
    if "web" in nome:
        return "web"
    return None


def carregar_todos_os_logs(pasta_logs):
    """
    Lê todos os arquivos de log da pasta e retorna lista unificada.
    Usa os.listdir() para encontrar os arquivos.
    """
    todos_eventos = []

    try:
        arquivos = os.listdir(pasta_logs)
    except FileNotFoundError:
        print(f"[ERRO] Pasta de logs não encontrada: {pasta_logs}")
        return todos_eventos

    if not arquivos:
        print(f"[INFO] Pasta {pasta_logs} está vazia")
        return todos_eventos

    for nome_arquivo in arquivos:
        fonte = _identificar_fonte_pelo_nome(nome_arquivo)
        if fonte is None:
            print(f"[AVISO] Não sei identificar a fonte do arquivo {nome_arquivo}, pulando")
            continue

        caminho_completo = os.path.join(pasta_logs, nome_arquivo)
        eventos_do_arquivo = carregar_log(caminho_completo, fonte)
        todos_eventos.extend(eventos_do_arquivo)

    return todos_eventos


if __name__ == "__main__":
    # Teste rápido só desta função, com uma linha de exemplo
    linha_teste = "2025-02-20 08:15:01 FAIL usuario=admin ip=185.220.101.1"
    resultado = parsear_linha_auth(linha_teste)
    print(resultado)

    linha_teste_fw = "2025-02-20 08:10:02 BLOCK proto=TCP src=185.220.101.1 dst=10.0.0.1 dport=22"
    resultado_fw = parsear_linha_firewall(linha_teste_fw)
    print(resultado_fw)

    linha_teste_web = "2025-02-20 08:20:15 GET url=/search?q=<script>alert(1)</script> ip=45.33.32.156 status=400"
    resultado_web = parsear_linha_web(linha_teste_web)
    print(resultado_web)

    print("\n--- Testando carregar_log ---")
    eventos_auth = carregar_log("logs/auth.log", "auth")
    print(f"auth.log: {len(eventos_auth)} eventos carregados")

    # Teste de arquivo inexistente
    eventos_fake = carregar_log("logs/naoexiste.log", "auth")
    print(f"arquivo inexistente: {len(eventos_fake)} eventos (esperado: 0)")

    print("\n--- Testando carregar_todos_os_logs ---")
    todos = carregar_todos_os_logs("logs")
    contagem_por_fonte = {}
    for evento in todos:
        contagem_por_fonte[evento["fonte"]] = contagem_por_fonte.get(evento["fonte"], 0) + 1
    print(f"Total geral: {len(todos)} eventos")
    print(f"Por fonte: {contagem_por_fonte}")
