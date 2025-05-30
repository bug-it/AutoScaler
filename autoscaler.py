#!/usr/bin/env python3
import os
import subprocess
import pwd
import psutil
import shlex
import signal

# Paleta de cores
CINZA = '\033[90m'
VERDE = '\033[92m'
AMARELO = '\033[93m'
AZUL = '\033[94m'
VERMELHO = '\033[91m'
RESET = '\033[0m'
LINHA = '=' * 80

def limpar_tela():
    os.system('clear')

def cabecalho(titulo):
    print(f"\n{VERDE}{LINHA}")
    print(f"      {titulo}")
    print(f"{LINHA}{RESET}\n")

def buscar_suid_sgid():
    cabecalho("Arquivos com bit SUID/SGID ativos (perigosos para escalonamento)")
    try:
        resultado = subprocess.check_output(
            "find / \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null", shell=True, text=True
        )
        arquivos = resultado.strip().split('\n')
        if arquivos and arquivos[0]:
            for f in arquivos:
                print(f"{AMARELO}{f}{RESET}")
            return arquivos
        else:
            print(f"{VERDE}Nenhum arquivo SUID/SGID encontrado.{RESET}")
            return []
    except subprocess.CalledProcessError:
        print(f"{VERMELHO}Erro ao buscar arquivos SUID/SGID.{RESET}")
        return []

def tentar_escalonar(arquivos):
    cabecalho("Tentando Escalonar Privilégios com Arquivos SUID/SGID")

    # Comandos "seguros" e comuns para tentar abrir shell ou listar info
    comandos_testes = [
        "-p",      # exemplo: bash -p para preservar privilégios
        "--help",  # para ver se exibe ajuda (não trava)
        "-h",      # outra variante help
    ]

    for arquivo in arquivos:
        print(f"{AZUL}Testando arquivo: {arquivo}{RESET}")
        # Tentaremos executar com cada argumento de teste
        for arg in comandos_testes:
            try:
                cmd = [arquivo, arg]
                print(f"  Executando: {' '.join(shlex.quote(c) for c in cmd)}")
                # subprocess.run com timeout e captura
                res = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=3,
                    check=False
                )
                saida = res.stdout.strip()
                erro = res.stderr.strip()
                if saida:
                    print(f"    {VERDE}Output:{RESET}\n{saida}")
                if erro:
                    print(f"    {VERMELHO}Erro:{RESET}\n{erro}")
                if not saida and not erro:
                    print(f"    {CINZA}Sem saída.{RESET}")
            except subprocess.TimeoutExpired:
                print(f"    {VERMELHO}Timeout: comando demorou demais e foi abortado.{RESET}")
            except Exception as e:
                print(f"    {VERMELHO}Erro ao executar: {e}{RESET}")
        print()

def buscar_arquivos_suspeitos():
    cabecalho("Arquivos com permissão de escrita para 'outros' (perigosos)")
    try:
        resultado = subprocess.check_output(
            "find /usr/bin -type f -perm -o=w -exec ls -l {} + 2>/dev/null", shell=True, text=True
        )
        linhas = resultado.strip().split('\n')
        if linhas and linhas[0]:
            for l in linhas:
                print(f"{AMARELO}{l}{RESET}")
        else:
            print(f"{VERDE}Nenhum arquivo com permissão suspeita em /usr/bin encontrado.{RESET}")
    except subprocess.CalledProcessError:
        print(f"{VERMELHO}Erro ao buscar arquivos com permissão suspeita.{RESET}")

def listar_usuarios_sudo():
    cabecalho("Usuários no grupo sudo")
    try:
        resultado = subprocess.check_output("getent group sudo", shell=True, text=True)
        partes = resultado.strip().split(':')
        if len(partes) > 3 and partes[3]:
            usuarios = partes[3].split(',')
            print(f"{VERDE}Usuários com privilégios sudo: {AMARELO}{', '.join(usuarios)}{RESET}")
        else:
            print(f"{VERMELHO}Nenhum usuário no grupo sudo encontrado.{RESET}")
    except subprocess.CalledProcessError:
        print(f"{VERMELHO}Erro ao listar usuários do grupo sudo.{RESET}")

def buscar_arquivos_escrita_usuario():
    cabecalho("Arquivos com permissão de escrita para usuários comuns (outros)")
    try:
        resultado = subprocess.check_output(
            "find / -type f -perm -o=w -exec ls -l {} + 2>/dev/null", shell=True, text=True
        )
        linhas = resultado.strip().split('\n')
        if linhas and linhas[0]:
            for l in linhas:
                print(f"{AMARELO}{l}{RESET}")
        else:
            print(f"{VERDE}Nenhum arquivo com permissão de escrita para outros encontrado.{RESET}")
    except subprocess.CalledProcessError:
        print(f"{VERMELHO}Erro ao buscar arquivos com permissão de escrita para outros.{RESET}")

def buscar_servicos_com_priviligios():
    cabecalho("Serviços Rodando com Privilégios Elevados (processos com UID=0)")

    processos_root = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'uids']):
        try:
            if proc.info['uids'] and proc.info['uids'].real == 0:
                processos_root.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if processos_root:
        for p in processos_root:
            print(f"PID: {p['pid']:<6} Nome: {AMARELO}{p['name']}{RESET} Usuário: {VERDE}{p['username']}{RESET}")
    else:
        print(f"{VERMELHO}Nenhum processo rodando como root detectado.{RESET}")
    print()

def buscar_binarios_suspeitos():
    cabecalho("Binários comuns usados para escalonamento de privilégios")
    binarios = [
        "/bin/bash", "/bin/sh", "/usr/bin/perl", "/usr/bin/python3",
        "/usr/bin/vim", "/usr/bin/nano", "/usr/bin/find", "/usr/bin/wget",
        "/usr/bin/curl", "/usr/bin/ssh"
    ]
    for b in binarios:
        if os.path.isfile(b):
            try:
                st = os.stat(b)
                permissao = oct(st.st_mode)[-3:]
                dono = pwd.getpwuid(st.st_uid).pw_name
                grupo = pwd.getpwuid(st.st_gid).pw_name
                print(f"{AMARELO}{b}{RESET} - Permissões: {VERDE}{permissao}{RESET} - Dono: {VERDE}{dono}{RESET} - Grupo: {VERDE}{grupo}{RESET}")
            except Exception as e:
                print(f"{VERMELHO}Erro ao verificar {b}: {e}{RESET}")
        else:
            print(f"{CINZA}Arquivo não encontrado: {b}{RESET}")
    print()

def main():
    limpar_tela()
    print(f"\n{VERDE}{LINHA}")
    print("        Auditoria para Possíveis Escalonamentos de Privilégios")
    print(f"{LINHA}{RESET}\n")

    arquivos_suid_sgid = buscar_suid_sgid()
    buscar_arquivos_suspeitos()
    listar_usuarios_sudo()
    buscar_arquivos_escrita_usuario()
    buscar_servicos_com_priviligios()
    buscar_binarios_suspeitos()

    if arquivos_suid_sgid:
        tentar_escalonar(arquivos_suid_sgid)

    print(f"{VERDE}{LINHA}")
    print("Auditoria concluída com sucesso!")
    print(f"{LINHA}{RESET}\n")

if __name__ == "__main__":
    main()
