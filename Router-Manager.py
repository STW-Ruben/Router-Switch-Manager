#!/usr/bin/env python3
# ============================================================
#  ROUTER MANAGER v3.0  –  Cisco IOS
# ============================================================

import paramiko
import time
import sys
import re

# ============================================================
#  LOGGING CIFRADO  (AES-256-CBC via cryptography)
# ============================================================

import os
import json
import datetime

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding as sym_padding
    _CRYPTO_OK = True
except ImportError:
    _CRYPTO_OK = False

# Clave y IV derivados de una passphrase hardcodeada + salt fijo.
# En produccion puedes pedir la clave al usuario al inicio.
_LOG_KEY  = b"CiscoMgr_SecureKey_AES256_32byte"   # 32 bytes = AES-256
_LOG_FILE = "session_log.enc"


def _aes_encrypt(plaintext: str) -> bytes:
    """Cifra plaintext con AES-256-CBC y devuelve iv+ciphertext."""
    iv        = os.urandom(16)
    padder    = sym_padding.PKCS7(128).padder()
    padded    = padder.update(plaintext.encode()) + padder.finalize()
    cipher    = Cipher(algorithms.AES(_LOG_KEY), modes.CBC(iv), backend=default_backend())
    enc       = cipher.encryptor()
    ct        = enc.update(padded) + enc.finalize()
    return iv + ct


def _aes_decrypt(data: bytes) -> str:
    """Descifra iv+ciphertext y devuelve el plaintext."""
    iv        = data[:16]
    ct        = data[16:]
    cipher    = Cipher(algorithms.AES(_LOG_KEY), modes.CBC(iv), backend=default_backend())
    dec       = cipher.decryptor()
    padded    = dec.update(ct) + dec.finalize()
    unpadder  = sym_padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode()


def log_action(action: str, detail: str = ""):
    """Registra una accion en el log cifrado."""
    if not _CRYPTO_OK:
        return
    entry = {
        "ts":     datetime.datetime.now().isoformat(),
        "action": action,
        "detail": detail,
    }
    line_enc = _aes_encrypt(json.dumps(entry))
    # Cada entrada: 4 bytes de longitud + datos cifrados
    with open(_LOG_FILE, "ab") as f:
        length = len(line_enc).to_bytes(4, "big")
        f.write(length + line_enc)


def dump_log():
    """Lee y muestra el log cifrado en pantalla."""
    if not _CRYPTO_OK:
        print("  [!] cryptography no instalado, log no disponible.")
        return
    if not os.path.exists(_LOG_FILE):
        print("  No hay log de sesion.")
        return
    print(f"\n{'='*50}")
    print(f"  LOG CIFRADO: {_LOG_FILE}")
    print(f"{'='*50}")
    with open(_LOG_FILE, "rb") as f:
        idx = 0
        while True:
            raw = f.read(4)
            if not raw or len(raw) < 4:
                break
            length = int.from_bytes(raw, "big")
            data   = f.read(length)
            if len(data) < length:
                break
            try:
                entry = json.loads(_aes_decrypt(data))
                print(f"  [{idx+1:03d}] {entry['ts']}  {entry['action']}  {entry['detail']}")
                idx += 1
            except Exception as e:
                print(f"  [ERR] Entrada corrupta: {e}")
    print(f"{'='*50}\n")


def _send_logged(channel, cmd, wait=1.5):
    """Wrapper de send() que ademas registra el comando en el log cifrado."""
    log_action("CMD", cmd.strip())
    return send(channel, cmd, wait)


def _send_long_logged(channel, cmd):
    """Wrapper de send_long() con logging cifrado."""
    log_action("CMD_LONG", cmd.strip())
    return send_long(channel, cmd)



# ============================================================
#  SSH  –  auto-accept host key + soporte para cifrados legacy Cisco IOS
# ============================================================


# ============================================================
#  CONEXION  –  Telnet + SSH con fallback automatico
#  Si el metodo elegido falla, ofrece intentar el otro.
#  Telnet: socket raw que simula terminal IOS.
#  SSH:    paramiko con negociacion automatica + fallback legacy.
# ============================================================

import socket as _socket

# ---- Helpers SSH (host key + algoritmos legacy) ----

class _AcceptAllKeys(paramiko.MissingHostKeyPolicy):
    """Acepta cualquier host key sin verificar (equivalente a 'yes' en OpenSSH)."""
    def missing_host_key(self, client, hostname, key):
        fp = ":".join(f"{b:02x}" for b in key.get_fingerprint())
        print(f"  [*] Host key de {hostname}  tipo={key.get_name()}  fp={fp}")
        print( "      Aceptado automaticamente.")

_DISABLED_ALGORITHMS = {
    "keys":    ["rsa-sha2-256", "rsa-sha2-512"],
    "pubkeys": ["rsa-sha2-256", "rsa-sha2-512"],
}

_CISCO_CONNECT_KWARGS = dict(
    look_for_keys=False,
    allow_agent=False,
    timeout=15,
    disabled_algorithms=_DISABLED_ALGORITHMS,
)

def _try_connect(host, username, password, extra_transport_args=None):
    """Conexion SSH via SSHClient con auto-accept de host key."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(_AcceptAllKeys())
    client.connect(host, port=22, username=username,
                   password=password, **_CISCO_CONNECT_KWARGS)
    channel = client.invoke_shell()
    time.sleep(1.5)
    channel.recv(65535)
    return client, channel


# ---- Clase de canal compatible para Telnet ----
# Envuelve un socket raw de telnet en una interfaz identica
# a la de un paramiko.Channel para que el resto del codigo
# no necesite saber si esta conectado por SSH o Telnet.

IAC  = bytes([255])
DONT = bytes([254])
DO   = bytes([253])
WONT = bytes([252])
WILL = bytes([251])
SB   = bytes([250])
SE   = bytes([240])
ECHO = bytes([1])
SGA  = bytes([3])

class TelnetChannel:
    """Socket telnet envuelto en la misma interfaz que paramiko.Channel."""

    def __init__(self, sock):
        self._sock = sock
        self._sock.settimeout(None)
        # Negociar opciones telnet basicas
        self._negotiate()

    def _negotiate(self):
        """Responde a las negociaciones IAC del servidor Cisco IOS."""
        self._sock.settimeout(2)
        try:
            buf = b""
            for _ in range(20):           # hasta 20 rondas de negociacion
                try:
                    chunk = self._sock.recv(256)
                except Exception:
                    break
                if not chunk:
                    break
                buf += chunk
                # procesar y responder opciones IAC
                i = 0
                while i < len(buf):
                    if buf[i:i+1] == IAC and i + 2 < len(buf):
                        cmd  = buf[i+1:i+2]
                        opt  = buf[i+2:i+3]
                        if cmd in (DO, WILL):
                            # Rechazar todo lo que pida el servidor
                            resp = IAC + (WONT if cmd == DO else DONT) + opt
                            self._sock.sendall(resp)
                        i += 3
                    else:
                        i += 1
                # Si el buffer ya no tiene mas IAC probablemente llego el prompt
                if IAC not in buf[-10:]:
                    break
        except Exception:
            pass
        self._sock.settimeout(None)

    def send(self, data):
        if isinstance(data, str):
            data = data.encode("utf-8", errors="replace")
        # Escapar IAC dentro de los datos
        data = data.replace(IAC, IAC + IAC)
        self._sock.sendall(data)

    def sendall(self, data):
        self.send(data)

    def recv(self, size):
        try:
            raw = self._sock.recv(size)
        except Exception:
            return b""
        # Filtrar secuencias IAC de la salida
        out = b""
        i = 0
        while i < len(raw):
            if raw[i:i+1] == IAC and i + 1 < len(raw):
                cmd = raw[i+1:i+2]
                if cmd in (DO, DONT, WILL, WONT) and i + 2 < len(raw):
                    i += 3
                elif cmd == SB:
                    # Saltar hasta SE
                    end = raw.find(IAC + SE, i + 2)
                    i = end + 2 if end != -1 else len(raw)
                elif cmd == IAC:
                    out += IAC
                    i += 2
                else:
                    i += 2
            else:
                out += raw[i:i+1]
                i += 1
        return out

    def settimeout(self, t):
        try:
            self._sock.settimeout(t)
        except Exception:
            pass

    def get_transport(self):
        return None

    def close(self):
        try:
            self._sock.close()
        except Exception:
            pass

    def fileno(self):
        return self._sock.fileno()


# ---- Conexion por Telnet ----

def connect_telnet(host, username, password, port=23):
    """Conecta al dispositivo por Telnet.
    Retorna (None, TelnetChannel) con la misma interfaz que connect_ssh."""
    print(f"\n[*] Conectando a {host}:{port} por Telnet ...")
    try:
        sock = _socket.create_connection((host, port), timeout=10)
        ch   = TelnetChannel(sock)
        print(f"  [OK] Conectado por Telnet a {host}:{port}")

        # Leer el banner/prompt inicial
        ch.settimeout(3)
        time.sleep(1.5)
        banner = ch.recv(4096).decode("utf-8", errors="replace")
        ch.settimeout(None)

        # Responder a "Username:" si aparece
        if "username" in banner.lower() or "user" in banner.lower():
            ch.send(username + "\n")
            time.sleep(1)
            resp = ch.recv(4096).decode("utf-8", errors="replace")
            banner += resp

        # Responder a "Password:"
        if "password" in banner.lower():
            ch.send(password + "\n")
            time.sleep(1)
            resp = ch.recv(4096).decode("utf-8", errors="replace")
            banner += resp

        log_action("TELNET", f"Conectado a {host}:{port}")
        return None, ch

    except Exception as e:
        print(f"  [!!] Telnet fallo: {e}")
        return None, None


# ---- Conexion por SSH (sin sys.exit, retorna None en error) ----

def connect_ssh(host, username, password):
    """Intenta conectar por SSH con negociacion automatica + fallback legacy.
    Retorna (client_or_transport, channel) o (None, None) si falla."""
    print(f"\n[*] Conectando a {host}:22 por SSH ...")

    # Intento 1: negociacion automatica
    try:
        client, channel = _try_connect(host, username, password)
        t = client.get_transport()
        print(f"  [OK] Conectado  cipher={t.remote_cipher}  kex={t.remote_mac}")
        log_action("SSH", f"Conectado a {host} cipher={t.remote_cipher} kex={t.remote_mac}")
        return client, channel
    except Exception as e:
        print(f"  [-] Intento 1 fallo: {e}")

    # Intento 2: kex legacy
    for kex in ["diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"]:
        try:
            t = paramiko.Transport((host, 22))
            sec = t.get_security_options()
            sec.kex     = [kex]
            sec.ciphers = ["aes128-cbc", "aes256-cbc", "3des-cbc"]
            sec.digests = ["hmac-sha1", "hmac-md5"]
            t.start_client(timeout=15)
            key = t.get_remote_server_key()
            fp  = ":".join(f"{b:02x}" for b in key.get_fingerprint())
            print(f"  [*] Host key  tipo={key.get_name()}  fp={fp}")
            print( "      Aceptado automaticamente.")
            t.auth_password(username, password)
            if not t.is_authenticated():
                raise paramiko.AuthenticationException("Autenticacion fallida")
            channel = t.open_session()
            channel.get_pty()
            channel.invoke_shell()
            time.sleep(1.5)
            channel.recv(65535)
            print(f"  [OK] Conectado con kex={kex}")
            log_action("SSH", f"Conectado a {host} kex={kex}")
            return t, channel
        except Exception as e:
            print(f"  [-] kex={kex} fallo: {e}")
            try:
                t.close()
            except Exception:
                pass

    print("  [!!] SSH fallo en todos los intentos.")
    return None, None


# ---- Conexion unificada con fallback automatico ----

def conectar(host, username, password, enable_password,
             metodo_preferido="ssh", telnet_port=23):
    """Intenta conectar con el metodo preferido.
    Si falla, pregunta si quiere intentar el otro metodo automaticamente.
    Retorna (conn_obj, channel, metodo_usado) o llama sys.exit si el
    usuario no quiere reintentar."""

    metodos = ["ssh", "telnet"] if metodo_preferido == "ssh" else ["telnet", "ssh"]

    conn_obj, channel, metodo_ok = None, None, None

    for metodo in metodos:
        if metodo == "ssh":
            conn_obj, channel = connect_ssh(host, username, password)
        else:
            conn_obj, channel = connect_telnet(host, username, password, telnet_port)

        if channel is not None:
            metodo_ok = metodo
            break
        else:
            # Fallo — ofrecer el otro metodo
            otro = "Telnet" if metodo == "ssh" else "SSH"
            print(f"\n  [!] {metodo.upper()} fallo.")
            r = input(f"  ¿Intentar con {otro}? (s/n): ").strip().lower()
            if r != "s":
                print("  [!!] No se pudo establecer conexion. Saliendo.")
                sys.exit(1)
            # Si es telnet el siguiente intento, pedir puerto
            if otro.lower() == "telnet":
                p = input("  Puerto Telnet (Enter=23): ").strip()
                telnet_port = int(p) if p.isdigit() else 23

    if channel is None:
        print("  [!!] No se pudo conectar por ningun metodo. Saliendo.")
        sys.exit(1)

    print(f"\n  [OK] Sesion establecida via {metodo_ok.upper()}")

    # Entrar a enable despues de conectar
    enter_enable(channel, enable_password)
    return conn_obj, channel, metodo_ok


# ---- Reconectar desde dentro del menu ----

def reconectar_desde_menu(channel):
    """Conecta a otro dispositivo DESDE EL ROUTER usando ssh o telnet IOS.
    El router es quien abre la conexion — la PC no interviene en absoluto."""
    print("\n  == NUEVA CONEXION DESDE EL ROUTER ==")
    print("  El router usara su propia IP para conectarse al destino.")
    print("  La PC atacante no participa en esta conexion.")
    print()
    host       = input("  IP del dispositivo destino : ").strip()
    user       = input("  Usuario                    : ").strip()
    password   = input("  Password                   : ").strip()
    enable_pwd = input("  Enable Password            : ").strip()
    print("  Metodo:")
    print("   1  SSH")
    print("   2  Telnet")
    m = input("  Opcion (Enter=SSH): ").strip()
    metodo = "telnet" if m == "2" else "ssh"
    if metodo == "ssh":
        port = input("  Puerto SSH (Enter=22): ").strip() or "22"
    else:
        port = input("  Puerto Telnet (Enter=23): ").strip() or "23"

    ok = _conectar_via_router(channel, host, user, password, enable_pwd, metodo, port)

    if not ok:
        otro   = "Telnet" if metodo == "ssh" else "SSH"
        r = input(f"  {metodo.upper()} fallo. ¿Intentar con {otro}? (s/n): ").strip().lower()
        if r == "s":
            metodo2 = "telnet" if metodo == "ssh" else "ssh"
            port2   = input(f"  Puerto {otro} (Enter={'23' if metodo2=='telnet' else '22'}): ").strip()
            port2   = port2 or ("23" if metodo2 == "telnet" else "22")
            ok = _conectar_via_router(channel, host, user, password, enable_pwd, metodo2, port2)
        if not ok:
            print("  [!] No se pudo conectar por ningun metodo.")
            return

    print(f"\n  [*] Conectado a {host} via el router.")
    print(f"  [*] Escribe  exit_menu  para volver al menu del script.")
    _router_shell_loop(channel)


# ============================================================
#  UTILIDADES CORE
# ============================================================

def recv_all(channel, timeout=4):
    """Lee TODO lo que haya en el buffer esperando hasta 'timeout' segundos sin datos."""
    channel.settimeout(timeout)
    output = ""
    while True:
        try:
            chunk = channel.recv(8192).decode("utf-8", errors="replace")
            if not chunk:
                break
            output += chunk
            # si el prompt termina en '>' o '#' y no hay más datos, salir
            if re.search(r'[>#]\s*$', output):
                # espera breve y reintenta una vez para capturar paginacion
                time.sleep(0.3)
                try:
                    extra = channel.recv(8192).decode("utf-8", errors="replace")
                    if not extra:
                        break
                    output += extra
                except Exception:
                    break
        except Exception:
            break
    channel.settimeout(None)
    return output


def send(channel, cmd, wait=1.5):
    """Envía un comando y devuelve la salida."""
    channel.send(cmd + "\n")
    time.sleep(wait)
    return recv_all(channel, timeout=wait + 1)


def send_long(channel, cmd):
    """Para comandos que generan mucha salida (show route, show run, etc.).
    Desactiva paginacion, ejecuta y restaura.
    Maneja el caso donde el canal quedo en modo usuario tras una sesion interactiva."""
    # Primero verificar que el canal sigue activo enviando un enter vacio
    try:
        channel.send("\n")
        time.sleep(0.5)
        probe = recv_all(channel, timeout=1)
    except Exception as e:
        raise OSError(f"Canal SSH cerrado: {e}")

    # Si el prompt muestra ">" estamos en modo usuario — volver a enable
    if re.search(r"\w+>\s*$", probe):
        channel.send("enable\n")
        time.sleep(0.5)
        recv_all(channel, timeout=1)

    # Desactivar paginacion
    channel.send("terminal length 0\n")
    time.sleep(0.8)
    recv_all(channel, timeout=1)
    channel.send(cmd + "\n")
    time.sleep(2)
    out = recv_all(channel, timeout=5)
    channel.send("terminal length 24\n")
    time.sleep(0.5)
    recv_all(channel, timeout=1)
    return out


def check_error(output):
    errors = ["% Invalid", "% Incomplete", "% Ambiguous",
              "% Access denied", "% Error", "% Bad"]
    for err in errors:
        if err in output:
            print(f"  [!] Error IOS: {err}")
            return True
    return False


def confirm(msg="  ¿Confirmar? (s/n): "):
    return input(msg).strip().lower() == 's'


def enter_enable(channel, enable_password):
    """Entra al modo enable con verificacion."""
    send(channel, "enable", 0.8)
    out = send(channel, enable_password, 1)
    if "#" in out:
        print("  [OK] Modo enable activo.")
        log_action("AUTH", "Modo enable activado correctamente")
    else:
        print("  [!] Advertencia: no se confirmo modo enable. Revise el password.")
        log_action("AUTH", "WARN: modo enable no confirmado")

# ============================================================
#  DETECCION DE DISPOSITIVO  (IOS, modelo, version)
# ============================================================

def detect_device(channel):
    print("\n[*] Detectando dispositivo Cisco IOS...")
    raw = send_long(channel, "show version")

    hostname   = "Desconocido"
    ios_ver    = "Desconocido"
    model      = "Desconocido"
    uptime_str = "Desconocido"
    ios_type   = "IOS"

    # hostname + uptime
    m = re.search(r'^(\S+)\s+uptime is\s+(.+)', raw, re.MULTILINE)
    if m:
        hostname   = m.group(1)
        uptime_str = m.group(2).strip()

    # version IOS
    m = re.search(r'Cisco IOS.*?[Vv]ersion\s+(\S+)', raw)
    if m:
        ios_ver = m.group(1).rstrip(',')

    # tipo de IOS
    if "IOS-XE" in raw or "IOS XE" in raw:
        ios_type = "IOS-XE"
    elif "IOS XR" in raw:
        ios_type = "IOS-XR"

    # modelo  – busca patron "cisco XXXX" donde XXXX puede ser c7200, 2911, ASR1001, etc.
    patterns = [
        r'[Cc]isco\s+(C\d[\w\-]+)',          # C7200, C3750, C2911
        r'[Cc]isco\s+(\d{3,4}[\w\-]*)',       # 7206VXR, 2921, 891
        r'[Cc]isco\s+([A-Z]{2,5}\d[\w\-]+)',  # ASR1001, ISR4321, ISRV
        r'[Cc]isco\s+([\w]{2,}-[\w]+-[\w]+)', # WS-C3560-24PS etc.
        r'[Cc]isco\s+(WS-C[\w\-]+)',          # Catalyst WS
    ]
    for pat in patterns:
        m = re.search(pat, raw)
        if m:
            model = m.group(1)
            break

    # si no encontro nada buscar linea "Hardware:  cisco ..."
    if model == "Desconocido":
        m = re.search(r'[Hh]ardware.*?[Cc]isco\s+(\S+)', raw)
        if m:
            model = m.group(1)

    print(f"  Hostname   : {hostname}")
    print(f"  Modelo     : {model}")
    print(f"  IOS Tipo   : {ios_type}")
    print(f"  IOS Version: {ios_ver}")
    print(f"  Uptime     : {uptime_str}")
    print()
    log_action("DEVICE", f"hostname={hostname} model={model} ios={ios_type} ver={ios_ver}")
    return hostname, model, ios_type, ios_ver

# ============================================================
#  INTERFACES
# ============================================================

def configure_interface(channel):
    iface = input("  Interface (ej: GigabitEthernet0/0 o g0/0): ")
    ip    = input("  IP: ")
    mask  = input("  Mascara: ")
    desc  = input("  Descripcion (Enter para omitir): ").strip()
    send(channel, "configure terminal")
    send(channel, f"interface {iface}")
    if desc:
        send(channel, f"description {desc}")
    check_error(send(channel, f"ip address {ip} {mask}"))
    check_error(send(channel, "no shutdown"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Interface configurada.")

def shutdown_interface(channel):
    iface = input("  Interface: ")
    if not confirm(f"  ¿Apagar {iface}? (s/n): "):
        return
    send(channel, "configure terminal")
    send(channel, f"interface {iface}")
    check_error(send(channel, "shutdown"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Interface apagada.")

def noshutdown_interface(channel):
    iface = input("  Interface: ")
    send(channel, "configure terminal")
    send(channel, f"interface {iface}")
    check_error(send(channel, "no shutdown"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Interface levantada.")

def remove_ip_interface(channel):
    iface = input("  Interface: ")
    send(channel, "configure terminal")
    send(channel, f"interface {iface}")
    check_error(send(channel, "no ip address"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] IP removida.")

def configure_secondary_ip(channel):
    iface = input("  Interface: ")
    ip    = input("  IP secundaria: ")
    mask  = input("  Mascara: ")
    send(channel, "configure terminal")
    send(channel, f"interface {iface}")
    check_error(send(channel, f"ip address {ip} {mask} secondary"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] IP secundaria configurada.")

def configure_interface_bandwidth(channel):
    iface = input("  Interface: ")
    bw    = input("  Bandwidth en kbps: ")
    send(channel, "configure terminal")
    send(channel, f"interface {iface}")
    check_error(send(channel, f"bandwidth {bw}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Bandwidth configurado.")

def show_interfaces_brief(channel):
    print(send_long(channel, "show ip interface brief"))

def show_interface_detail(channel):
    iface = input("  Interface: ")
    print(send_long(channel, f"show interfaces {iface}"))

def show_interfaces_status(channel):
    print(send_long(channel, "show interfaces"))

# ============================================================
#  ROUTING / TABLAS
# ============================================================

def show_routes(channel):
    print(send_long(channel, "show ip route"))

def show_route_summary(channel):
    print(send_long(channel, "show ip route summary"))

def show_route_specific(channel):
    net = input("  Red o IP (ej: 192.168.1.0): ")
    print(send_long(channel, f"show ip route {net}"))

def add_static_route(channel):
    dest    = input("  Red destino: ")
    mask    = input("  Mascara: ")
    nexthop = input("  Next-hop o interface de salida: ")
    ad      = input("  Distancia administrativa (Enter=default): ").strip()
    cmd     = f"ip route {dest} {mask} {nexthop}"
    if ad:
        cmd += f" {ad}"
    send(channel, "configure terminal")
    check_error(send(channel, cmd))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Ruta estatica agregada.")

def delete_static_route(channel):
    dest    = input("  Red destino: ")
    mask    = input("  Mascara: ")
    nexthop = input("  Next-hop o interface: ")
    if not confirm(f"  ¿Eliminar ruta {dest}? (s/n): "):
        return
    send(channel, "configure terminal")
    check_error(send(channel, f"no ip route {dest} {mask} {nexthop}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Ruta eliminada.")

def flush_all_static_routes(channel):
    if not confirm("  [!!!] Eliminar TODAS las rutas estaticas. ¿Continuar? (s/n): "):
        return
    if not confirm("  [!!!] ULTIMA confirmacion. ¿Seguro? (s/n): "):
        return
    raw    = send_long(channel, "show running-config | include ^ip route")
    routes = re.findall(r'(ip route \S+ \S+ \S+.*)', raw)
    if not routes:
        print("  No se encontraron rutas estaticas.")
        return
    send(channel, "configure terminal")
    for r in routes:
        check_error(send(channel, f"no {r.strip()}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print(f"  [OK] {len(routes)} ruta(s) eliminada(s).")

def add_default_route(channel):
    nexthop = input("  Next-hop para ruta default 0.0.0.0/0: ")
    send(channel, "configure terminal")
    check_error(send(channel, f"ip route 0.0.0.0 0.0.0.0 {nexthop}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Ruta default configurada.")

def delete_default_route(channel):
    if not confirm("  [!] ¿Eliminar ruta default? (s/n): "):
        return
    nexthop = input("  Next-hop actual de la ruta default: ")
    send(channel, "configure terminal")
    check_error(send(channel, f"no ip route 0.0.0.0 0.0.0.0 {nexthop}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Ruta default eliminada.")

def show_arp_table(channel):
    print(send_long(channel, "show arp"))

def clear_arp_table(channel):
    if not confirm("  [!] ¿Limpiar tabla ARP? (s/n): "):
        return
    send(channel, "clear arp-cache", 3)
    print("  [OK] Tabla ARP limpiada.")

# ============================================================
#  OSPF
# ============================================================

def configure_ospf(channel):
    pid      = input("  Process ID OSPF: ")
    network  = input("  Red (ej: 192.168.1.0): ")
    wildcard = input("  Wildcard mask (ej: 0.0.0.255): ")
    area     = input("  Area (ej: 0): ")
    router_id = input("  Router-ID (Enter para omitir): ").strip()
    send(channel, "configure terminal")
    send(channel, f"router ospf {pid}")
    if router_id:
        check_error(send(channel, f"router-id {router_id}"))
    check_error(send(channel, f"network {network} {wildcard} area {area}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] OSPF configurado.")

def disable_ospf(channel):
    pid = input("  Process ID OSPF a eliminar: ")
    if not confirm(f"  [!] ¿Eliminar proceso OSPF {pid}? (s/n): "):
        return
    send(channel, "configure terminal")
    check_error(send(channel, f"no router ospf {pid}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] OSPF eliminado.")

def show_ospf_neighbors(channel):
    print(send_long(channel, "show ip ospf neighbor"))

def show_ospf_database(channel):
    print(send_long(channel, "show ip ospf database"))

def configure_ospf_auth(channel):
    iface  = input("  Interface: ")
    key_id = input("  Key ID (ej: 1): ")
    key    = input("  Key MD5: ")
    send(channel, "configure terminal")
    send(channel, f"interface {iface}")
    check_error(send(channel, "ip ospf authentication message-digest"))
    check_error(send(channel, f"ip ospf message-digest-key {key_id} md5 {key}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Autenticacion OSPF MD5 configurada.")

def configure_ospf_passive(channel):
    pid   = input("  Process ID OSPF: ")
    iface = input("  Interface pasiva: ")
    send(channel, "configure terminal")
    send(channel, f"router ospf {pid}")
    check_error(send(channel, f"passive-interface {iface}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Interface pasiva configurada.")

# ============================================================
#  EIGRP
# ============================================================

def configure_eigrp(channel):
    asn      = input("  AS Number EIGRP: ")
    network  = input("  Red: ")
    wildcard = input("  Wildcard mask: ")
    send(channel, "configure terminal")
    send(channel, f"router eigrp {asn}")
    check_error(send(channel, f"network {network} {wildcard}"))
    check_error(send(channel, "no auto-summary"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] EIGRP configurado.")

def disable_eigrp(channel):
    asn = input("  AS Number EIGRP a eliminar: ")
    if not confirm(f"  [!] ¿Eliminar EIGRP AS {asn}? (s/n): "):
        return
    send(channel, "configure terminal")
    check_error(send(channel, f"no router eigrp {asn}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] EIGRP eliminado.")

def show_eigrp_neighbors(channel):
    print(send_long(channel, "show ip eigrp neighbors"))

def show_eigrp_topology(channel):
    print(send_long(channel, "show ip eigrp topology"))

# ============================================================
#  RIP
# ============================================================

def configure_rip(channel):
    version = input("  Version RIP (1/2): ")
    network = input("  Red a anunciar: ")
    send(channel, "configure terminal")
    send(channel, "router rip")
    check_error(send(channel, f"version {version}"))
    check_error(send(channel, f"network {network}"))
    if version == "2":
        check_error(send(channel, "no auto-summary"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] RIP configurado.")

def disable_rip(channel):
    if not confirm("  [!] ¿Eliminar RIP? (s/n): "):
        return
    send(channel, "configure terminal")
    check_error(send(channel, "no router rip"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] RIP eliminado.")

# ============================================================
#  BGP
# ============================================================

def configure_bgp(channel):
    asn         = input("  AS local: ")
    neighbor_ip = input("  IP vecino BGP: ")
    neighbor_as = input("  AS vecino: ")
    send(channel, "configure terminal")
    send(channel, f"router bgp {asn}")
    check_error(send(channel, f"neighbor {neighbor_ip} remote-as {neighbor_as}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] BGP configurado.")

def disable_bgp(channel):
    asn = input("  AS BGP a eliminar: ")
    if not confirm(f"  [!!!] ¿Eliminar BGP AS {asn}? PELIGROSO. (s/n): "):
        return
    send(channel, "configure terminal")
    check_error(send(channel, f"no router bgp {asn}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] BGP eliminado.")

def show_bgp_summary(channel):
    print(send_long(channel, "show ip bgp summary"))

def show_bgp_table(channel):
    print(send_long(channel, "show ip bgp"))

# ============================================================
#  ACL
# ============================================================

def create_acl_standard(channel):
    acl    = input("  Numero ACL standard (1-99): ")
    action = input("  Accion (permit/deny): ")
    src    = input("  Origen (host X.X.X.X / red wildcard / any): ")
    send(channel, "configure terminal")
    check_error(send(channel, f"access-list {acl} {action} {src}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] ACL standard creada.")

def create_acl_extended(channel):
    acl    = input("  Numero ACL extendida (100-199): ")
    action = input("  Accion (permit/deny): ")
    proto  = input("  Protocolo (ip/tcp/udp/icmp): ")
    src    = input("  Origen (host X / red wildcard / any): ")
    dst    = input("  Destino (host X / red wildcard / any): ")
    port   = input("  Puerto destino (ej: eq 80 | Enter omitir): ").strip()
    cmd    = f"access-list {acl} {action} {proto} {src} {dst}"
    if port:
        cmd += f" {port}"
    send(channel, "configure terminal")
    check_error(send(channel, cmd))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] ACL extendida creada.")

def delete_acl(channel):
    acl = input("  Numero ACL a eliminar: ")
    if not confirm(f"  [!] ¿Eliminar ACL {acl}? (s/n): "):
        return
    send(channel, "configure terminal")
    check_error(send(channel, f"no access-list {acl}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] ACL eliminada.")

def apply_acl_interface(channel):
    acl       = input("  Numero ACL: ")
    iface     = input("  Interface: ")
    direction = input("  Direccion (in/out): ")
    send(channel, "configure terminal")
    send(channel, f"interface {iface}")
    check_error(send(channel, f"ip access-group {acl} {direction}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] ACL aplicada.")

def show_acls(channel):
    print(send_long(channel, "show ip access-lists"))

# ============================================================
#  NAT / PAT
# ============================================================

def configure_nat_overload(channel):
    acl          = input("  ACL que define la red interna: ")
    outside_if   = input("  Interface OUTSIDE (ej: g0/0): ")
    inside_if    = input("  Interface INSIDE  (ej: g0/1): ")
    send(channel, "configure terminal")
    send(channel, f"interface {outside_if}")
    check_error(send(channel, "ip nat outside"))
    send(channel, f"interface {inside_if}")
    check_error(send(channel, "ip nat inside"))
    check_error(send(channel, f"ip nat inside source list {acl} interface {outside_if} overload"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] NAT overload (PAT) configurado.")

def configure_nat_static(channel):
    local_ip  = input("  IP local interna: ")
    global_ip = input("  IP global externa: ")
    send(channel, "configure terminal")
    check_error(send(channel, f"ip nat inside source static {local_ip} {global_ip}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] NAT estatico configurado.")

def clear_nat_translations(channel):
    if not confirm("  [!] ¿Limpiar traducciones NAT dinamicas? (s/n): "):
        return
    send(channel, "clear ip nat translation *", 3)
    print("  [OK] Traducciones NAT limpiadas.")

def show_nat_translations(channel):
    print(send_long(channel, "show ip nat translations"))

def show_nat_stats(channel):
    print(send_long(channel, "show ip nat statistics"))

# ============================================================
#  DHCP
# ============================================================

def configure_dhcp_pool(channel):
    pool    = input("  Nombre del pool: ")
    network = input("  Red (ej: 192.168.1.0): ")
    mask    = input("  Mascara: ")
    gateway = input("  Gateway: ")
    dns     = input("  DNS (Enter omitir): ").strip()
    lease   = input("  Lease dias (Enter=1): ").strip() or "1"
    send(channel, "configure terminal")
    send(channel, f"ip dhcp pool {pool}")
    check_error(send(channel, f"network {network} {mask}"))
    check_error(send(channel, f"default-router {gateway}"))
    if dns:
        check_error(send(channel, f"dns-server {dns}"))
    check_error(send(channel, f"lease {lease}"))
    send(channel, "exit")
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Pool DHCP configurado.")

def exclude_dhcp_range(channel):
    start = input("  IP inicio a excluir: ")
    end   = input("  IP fin (Enter = solo una): ").strip()
    send(channel, "configure terminal")
    if end:
        check_error(send(channel, f"ip dhcp excluded-address {start} {end}"))
    else:
        check_error(send(channel, f"ip dhcp excluded-address {start}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Rango excluido.")

def delete_dhcp_pool(channel):
    pool = input("  Nombre del pool a eliminar: ")
    if not confirm(f"  [!] ¿Eliminar pool {pool}? (s/n): "):
        return
    send(channel, "configure terminal")
    check_error(send(channel, f"no ip dhcp pool {pool}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Pool eliminado.")

def show_dhcp_bindings(channel):
    print(send_long(channel, "show ip dhcp binding"))

def show_dhcp_pool(channel):
    print(send_long(channel, "show ip dhcp pool"))

def clear_dhcp_bindings(channel):
    if not confirm("  [!] ¿Limpiar todos los leases DHCP? (s/n): "):
        return
    send(channel, "clear ip dhcp binding *", 3)
    print("  [OK] Bindings DHCP limpiados.")

# ============================================================
#  USUARIOS Y SEGURIDAD
# ============================================================

def create_local_user(channel):
    user  = input("  Nuevo usuario: ")
    priv  = input("  Nivel de privilegio (0-15): ")
    pwd   = input("  Password: ")
    send(channel, "configure terminal")
    check_error(send(channel, f"username {user} privilege {priv} secret {pwd}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Usuario creado.")

def delete_local_user(channel):
    user = input("  Usuario a eliminar: ")
    if not confirm(f"  [!] ¿Eliminar usuario '{user}'? (s/n): "):
        return
    send(channel, "configure terminal")
    check_error(send(channel, f"no username {user}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Usuario eliminado.")

def change_enable_secret(channel):
    if not confirm("  [!] ¿Cambiar enable secret? (s/n): "):
        return
    new_pwd = input("  Nuevo enable secret: ")
    send(channel, "configure terminal")
    check_error(send(channel, f"enable secret {new_pwd}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Enable secret cambiado.")

def configure_ssh(channel):
    domain = input("  Dominio (para RSA keygen, ej: empresa.local): ")
    bits   = input("  Bits RSA (1024/2048, recomendado 2048): ")
    send(channel, "configure terminal")
    check_error(send(channel, f"ip domain-name {domain}"))
    out = send(channel, f"crypto key generate rsa modulus {bits}", 5)
    if "How many bits" in out:
        channel.send(f"{bits}\n")
        time.sleep(3)
        recv_all(channel)
    check_error(send(channel, "ip ssh version 2"))
    send(channel, "line vty 0 4")
    check_error(send(channel, "transport input ssh"))
    check_error(send(channel, "login local"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] SSH v2 configurado.")

def configure_console_password(channel):
    pwd = input("  Password de consola: ")
    send(channel, "configure terminal")
    send(channel, "line console 0")
    check_error(send(channel, f"password {pwd}"))
    check_error(send(channel, "login"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Password de consola configurado.")

def configure_vty_password(channel):
    pwd = input("  Password VTY: ")
    send(channel, "configure terminal")
    send(channel, "line vty 0 4")
    check_error(send(channel, f"password {pwd}"))
    check_error(send(channel, "login"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Password VTY configurado.")

def show_users(channel):
    print(send_long(channel, "show users"))

# ============================================================
#  SISTEMA / GLOBAL
# ============================================================

def set_hostname(channel):
    name = input("  Nuevo hostname: ")
    send(channel, "configure terminal")
    check_error(send(channel, f"hostname {name}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Hostname cambiado.")

def configure_ntp(channel):
    server = input("  IP servidor NTP: ")
    send(channel, "configure terminal")
    check_error(send(channel, f"ntp server {server}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] NTP configurado.")

def configure_syslog(channel):
    server = input("  IP servidor Syslog: ")
    level  = input("  Nivel (debugging/informational/warnings, Enter=informational): ").strip() or "informational"
    send(channel, "configure terminal")
    check_error(send(channel, f"logging {server}"))
    check_error(send(channel, f"logging trap {level}"))
    check_error(send(channel, "logging on"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Syslog configurado.")

def configure_snmp(channel):
    community = input("  Community string: ")
    access    = input("  Tipo (ro/rw): ")
    send(channel, "configure terminal")
    check_error(send(channel, f"snmp-server community {community} {access}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] SNMP configurado.")

def delete_snmp(channel):
    community = input("  Community a eliminar: ")
    send(channel, "configure terminal")
    check_error(send(channel, f"no snmp-server community {community}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Community SNMP eliminado.")

def configure_banner(channel):
    print("  Ingrese el banner (escriba EOF en linea sola para terminar):")
    lines = []
    while True:
        line = input()
        if line.strip() == "EOF":
            break
        lines.append(line)
    send(channel, "configure terminal")
    send(channel, "banner motd #")
    for line in lines:
        channel.send(line + "\n")
        time.sleep(0.1)
    channel.send("#\n")
    time.sleep(0.5)
    recv_all(channel)
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Banner configurado.")

def show_running_config(channel):
    print(send_long(channel, "show running-config"))

def show_startup_config(channel):
    print(send_long(channel, "show startup-config"))

def save_config(channel):
    out = send(channel, "write memory", 4)
    print(out)
    print("  [OK] Configuracion guardada.")

def show_cdp_neighbors(channel):
    print(send_long(channel, "show cdp neighbors detail"))

def show_processes_cpu(channel):
    print(send_long(channel, "show processes cpu sorted"))

def show_memory(channel):
    print(send_long(channel, "show memory statistics"))

def show_log(channel):
    print(send_long(channel, "show logging"))

def show_clock(channel):
    print(send(channel, "show clock"))

def configure_ip_sla(channel):
    num    = input("  Numero SLA: ")
    target = input("  IP destino (ping): ")
    freq   = input("  Frecuencia en segundos: ")
    send(channel, "configure terminal")
    send(channel, f"ip sla {num}")
    check_error(send(channel, f"icmp-echo {target}"))
    check_error(send(channel, f"frequency {freq}"))
    send(channel, "exit")
    check_error(send(channel, f"ip sla schedule {num} life forever start-time now"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] IP SLA configurado.")

def erase_startup_config(channel):
    if not confirm("  [!!!] PELIGRO EXTREMO: borrara startup-config. El router arranca sin config. ¿Continuar? (s/n): "):
        return
    if not confirm("  [!!!] ULTIMA oportunidad. ¿Seguro? (s/n): "):
        return
    out = send(channel, "erase startup-config", 5)
    if "confirm" in out.lower():
        channel.send("\n")
        time.sleep(2)
        recv_all(channel)
    print("  [OK] Startup-config borrada.")

def reload_device(channel):
    if not confirm("  [!!!] PELIGRO: reiniciara el router. Perdera conectividad. ¿Continuar? (s/n): "):
        return
    if not confirm("  [!!!] ¿Completamente seguro? (s/n): "):
        return
    channel.send("reload\n")
    time.sleep(2)
    out = recv_all(channel, timeout=3)
    if "confirm" in out.lower() or "proceed" in out.lower() or "[confirm]" in out.lower():
        channel.send("\n")
    print("  [!!] Reinicio iniciado. La conexion se perdera.")



# ============================================================
#  TUNEL SSH / SHELL REMOTO
#  IMPORTANTE: todos los comandos se ejecutan DENTRO del router
#  usando el canal SSH ya abierto (variable 'channel').
#  El router es quien inicia las conexiones, no la PC local.
# ============================================================

import threading
import socket
import select
import subprocess
import shutil
import sys as _sys

_tunnel_active = [False]
_tunnel_thread = [None]


def _send_interactive(channel, cmd, wait=2):
    """Envía un comando por el canal del router y devuelve la salida."""
    channel.send(cmd + "\n")
    time.sleep(wait)
    return recv_all(channel, timeout=wait + 1)


def _router_shell_loop(channel):
    """Modo shell interactivo completo sobre el canal SSH del router.
    El usuario escribe comandos que se ejecutan EN EL ROUTER.
    Escribe 'exit_menu' para volver al menu sin cerrar la sesion."""
    print("\n  [*] Modo shell interactivo EN EL ROUTER.")
    print("  [*] Los comandos se ejecutan directamente en el dispositivo.")
    print("  [*] Escribe  exit_menu  para volver al menu del script.")
    print("  [*] Escribe  exit       para cerrar la sesion del router.")
    print("-" * 50)

    # Activar modo raw TTY para que las teclas se envíen directamente
    import sys
    try:
        import tty, termios
        old_settings = termios.tcgetattr(sys.stdin)
        tty.setraw(sys.stdin.fileno())
        raw_mode = True
    except Exception:
        raw_mode = False

    # Buffer para detectar el comando "exit_menu" ANTES de enviar al router
    line_buf = b""

    try:
        while True:
            r, _, _ = select.select([channel, sys.stdin], [], [], 0.05)

            # Datos llegando DEL router -> mostrar en pantalla
            if channel in r:
                try:
                    data = channel.recv(4096)
                except Exception:
                    break
                if not data:
                    break
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()

            # Teclas del usuario -> acumular y decidir
            if sys.stdin in r:
                try:
                    ch = sys.stdin.buffer.read(1)
                except Exception:
                    break
                if not ch:
                    break

                if ch in (b"\r", b"\n"):
                    if line_buf.strip() == b"exit_menu":
                        # NO enviar al router — volver al menu
                        if raw_mode:
                            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
                        sys.stdout.buffer.write(b"\r\n")
                        sys.stdout.buffer.flush()
                        print("-" * 50)
                        print("  [*] Volviendo al menu del script...")
                        return
                    else:
                        # Enviar el buffer acumulado + enter al router
                        if line_buf:
                            channel.send(line_buf)
                        channel.send(ch)
                        line_buf = b""
                elif ch == b"\x7f" or ch == b"\x08":  # Backspace / DEL
                    if line_buf:
                        line_buf = line_buf[:-1]
                        # Erase en pantalla
                        sys.stdout.buffer.write(b"\x08 \x08")
                        sys.stdout.buffer.flush()
                    else:
                        channel.send(ch)
                else:
                    # Acumular — mostrar en pantalla pero NO enviar todavia
                    line_buf += ch
                    sys.stdout.buffer.write(ch)
                    sys.stdout.buffer.flush()

    except KeyboardInterrupt:
        pass
    finally:
        if raw_mode:
            try:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
            except Exception:
                pass

    print("\n" + "-" * 50)
    print("  [*] Sesion cerrada.")


def _conectar_via_router(channel, host, user, password, enable_pwd, metodo="ssh", port=None):
    """Envia el comando ssh o telnet al router y maneja el handshake completo
    (confirmacion de host key, password, enable). Deja el canal en modo interactivo.
    TODO el trafico va por el canal del router — NUNCA desde la PC local."""

    if metodo == "ssh":
        port = port or "22"
        if port == "22":
            cmd = f"ssh -l {user} {host}"
        else:
            cmd = f"ssh -l {user} -p {port} {host}"
    else:  # telnet
        port = port or "23"
        cmd = f"telnet {host} {port}"

    log_action(f"{metodo.upper()}_FROM_ROUTER", f"{user}@{host}:{port}")
    print(f"\n  [*] Ejecutando en el router: {cmd}")
    print("  [*] Manejando handshake automaticamente...")
    print("-" * 50)

    channel.send(cmd + "\n")

    # Esperar y procesar la respuesta en bucle hasta llegar al prompt
    # Maneja: yes/no (host key), Password:, enable, prompt # o >
    deadline = time.time() + 20
    accumulated = ""
    pwd_sent    = False
    enable_sent = False

    while time.time() < deadline:
        time.sleep(0.8)
        chunk = recv_all(channel, timeout=2)
        if chunk:
            accumulated += chunk
            _sys.stdout.write(chunk)
            _sys.stdout.flush()

        low = accumulated.lower()

        # Host key confirmation
        if ("yes/no" in low or "[fingerprint]" in low) and "yes" not in accumulated.split("yes/no")[-1][:5]:
            channel.send("yes\n")
            accumulated += "yes\n"
            continue

        # Password prompt
        if "password:" in low and not pwd_sent:
            channel.send(password + "\n")
            pwd_sent = True
            accumulated += "***\n"
            time.sleep(1)
            continue

        # Enable prompt (llego al modo user ">")
        if re.search(r"\w+>\s*$", accumulated) and enable_pwd and not enable_sent:
            channel.send("enable\n")
            time.sleep(0.5)
            channel.send(enable_pwd + "\n")
            enable_sent = True
            time.sleep(1)
            continue

        # Llego al modo privilegiado "#" — listo
        if re.search(r"\w+#\s*$", accumulated):
            break

        # Error de conexion
        if any(x in low for x in ["connection refused", "unable to connect",
                                    "% connection", "timed out", "error opening"]):
            print(f"\n  [!] Conexion rechazada o fallida.")
            return False

    _sys.stdout.write("\n")
    return True


def ssh_shell_desde_router(channel):
    """SSH desde el ROUTER al destino — usa la IP del router, evade NAT."""
    print("\n  == SSH DESDE EL ROUTER ==")
    print("  El ROUTER abre la conexion SSH. La PC no toca nada.")
    print()
    host       = input("  Host destino    : ").strip()
    port       = input("  Puerto (Enter=22): ").strip() or "22"
    user       = input("  Usuario         : ").strip()
    password   = input("  Password SSH    : ").strip()
    enable_pwd = input("  Enable password (Enter si no tiene): ").strip()

    ok = _conectar_via_router(channel, host, user, password, enable_pwd, "ssh", port)
    if not ok:
        # SSH fallo — ofrecer telnet
        r = input("  SSH fallo. ¿Intentar con Telnet? (s/n): ").strip().lower()
        if r == "s":
            tport = input("  Puerto Telnet (Enter=23): ").strip() or "23"
            ok = _conectar_via_router(channel, host, user, password, enable_pwd, "telnet", tport)
        if not ok:
            print("  [!] No se pudo conectar.")
            return

    print("  [*] Escribe  exit_menu  para volver al menu del script.")
    _router_shell_loop(channel)


def telnet_desde_router(channel):
    """Telnet desde el ROUTER al destino — usa la IP del router, evade NAT."""
    print("\n  == TELNET DESDE EL ROUTER ==")
    print("  El ROUTER abre la conexion Telnet. La PC no toca nada.")
    print()
    host       = input("  Host destino      : ").strip()
    port       = input("  Puerto (Enter=23)  : ").strip() or "23"
    user       = input("  Usuario           : ").strip()
    password   = input("  Password Telnet   : ").strip()
    enable_pwd = input("  Enable password (Enter si no tiene): ").strip()

    ok = _conectar_via_router(channel, host, user, password, enable_pwd, "telnet", port)
    if not ok:
        # Telnet fallo — ofrecer SSH
        r = input("  Telnet fallo. ¿Intentar con SSH? (s/n): ").strip().lower()
        if r == "s":
            sport = input("  Puerto SSH (Enter=22): ").strip() or "22"
            ok = _conectar_via_router(channel, host, user, password, enable_pwd, "ssh", sport)
        if not ok:
            print("  [!] No se pudo conectar.")
            return

    print("  [*] Escribe  exit_menu  para volver al menu del script.")
    _router_shell_loop(channel)


def ssh_shell_interactivo(channel):
    """Shell interactivo directo en el router actual.
    El usuario puede escribir cualquier comando IOS."""
    print("\n  == SHELL INTERACTIVO EN EL ROUTER ACTUAL ==")
    print("  Escribe comandos IOS directamente.")
    print("  Escribe  exit_menu  para volver al menu del script.")
    print("-" * 50)
    log_action("SHELL_INTERACTIVO", "Shell directo en router")
    _router_shell_loop(channel)


def ssh_tunel_menu(channel):
    """Sub-menu de conexion remota — todo via el router, nunca la PC."""
    opciones = [
        ("Shell interactivo en el router actual",        ssh_shell_interactivo),
        ("SSH  desde el router a otro dispositivo",      ssh_shell_desde_router),
        ("Telnet desde el router a otro dispositivo",    telnet_desde_router),
    ]
    print("\n  ============================================")
    print("    CONEXION REMOTA  (desde el router)")
    print("    La PC NO participa — usa la IP del router")
    print("  ============================================")
    for i, (desc, _) in enumerate(opciones, 1):
        print(f"   {i}  {desc}")
    print("   0  Volver")
    print("  ============================================")
    sub = input("  Opcion: ").strip()
    if sub == "0" or not sub.isdigit():
        return
    idx = int(sub) - 1
    if 0 <= idx < len(opciones):
        opciones[idx][1](channel)


# ============================================================
#  CONECTIVIDAD  –  Ping, traceroute, port-scan
#  IMPORTANTE: ejecutados DESDE EL ROUTER via comandos IOS,
#  no desde la PC local.
# ============================================================

def _parse_ping_ios(output):
    """Parsea la salida del ping de Cisco IOS y retorna estadisticas."""
    # Ejemplo IOS: "Success rate is 80 percent (4/5), round-trip min/avg/max = 1/2/4 ms"
    success = re.search(r'Success rate is (\d+) percent \((\d+)/(\d+)\)', output)
    rtt     = re.search(r'round-trip min/avg/max = ([\d/]+) ms', output)
    if success:
        pct  = success.group(1)
        recv = success.group(2)
        sent = success.group(3)
        rtt_str = rtt.group(1) if rtt else "N/A"
        return True, f"{recv}/{sent} paquetes ({pct}%)  RTT: {rtt_str} ms"
    # Ping fallido
    if "!" in output:
        return True, "Al menos un paquete respondio"
    return False, "Sin respuesta"


def conectividad_ping_simple(channel):
    """Ping desde el router a un host."""
    print("\n  == PING DESDE EL ROUTER ==")
    host  = input("  Host o IP destino: ").strip()
    count = input("  Cantidad de pings (Enter=5): ").strip() or "5"
    src   = input("  Interface/IP origen (Enter para default): ").strip()

    cmd = f"ping {host} repeat {count}"
    if src:
        cmd += f" source {src}"

    print(f"\n  [*] Ejecutando en el router: {cmd}")
    print("-" * 44)
    out = send_long(channel, cmd)
    print(out)
    print("-" * 44)
    ok, stats = _parse_ping_ios(out)
    estado = "ALCANZABLE" if ok else "NO RESPONDE"
    print(f"  Resultado: {host} -> {estado}  {stats}")
    log_action("PING", f"{host} count={count} resultado={estado} stats={stats}")


def conectividad_ping_extendido(channel):
    """Ping extendido IOS — permite configurar todos los parametros."""
    print("\n  == PING EXTENDIDO IOS ==")
    print("  Se ejecuta el modo ping extendido del router.")
    print("  El router pedira los parametros interactivamente.")
    print("  Escribe  exit_menu  cuando termines para volver.")
    print("-" * 44)
    log_action("PING_EXTENDIDO", "modo interactivo")
    channel.send("ping\n")
    time.sleep(1)
    _router_shell_loop(channel)


def conectividad_ping_multiple(channel):
    """Ping a multiples hosts desde el router."""
    print("\n  == PING MULTIPLE DESDE EL ROUTER ==")
    print("  Ingresa hosts separados por coma")
    print("  Ej: 192.168.1.1,192.168.1.2,10.0.0.1")
    print("  Ej: 192.168.1.0/24  (barre .1 a .254)")
    raw = input("  Hosts o red: ").strip()

    targets = []
    if "/" in raw and "," not in raw:
        base = raw.rsplit(".", 1)[0]
        targets = [f"{base}.{i}" for i in range(1, 255)]
    else:
        targets = [h.strip() for h in raw.split(",") if h.strip()]

    if not targets:
        print("  No hay hosts validos.")
        return

    count = input("  Pings por host (Enter=2): ").strip() or "2"
    print(f"\n  [*] Enviando ping a {len(targets)} host(s) desde el router...")
    print("-" * 44)

    up, down = 0, 0
    for host in targets:
        cmd = f"ping {host} repeat {count} timeout 2"
        out = send_long(channel, cmd)
        ok, stats = _parse_ping_ios(out)
        estado = "UP  " if ok else "DOWN"
        print(f"  {estado}  {host:<20}  {stats}")
        if ok:
            up += 1
        else:
            down += 1

    print("-" * 44)
    print(f"  Total: {len(targets)}  |  UP: {up}  |  DOWN: {down}")
    log_action("PING_SWEEP", f"targets={len(targets)} up={up} down={down}")


def conectividad_traceroute(channel):
    """Traceroute desde el router."""
    print("\n  == TRACEROUTE DESDE EL ROUTER ==")
    host = input("  Host o IP destino: ").strip()
    src  = input("  IP/Interface origen (Enter para default): ").strip()

    cmd = f"traceroute {host}"
    if src:
        cmd += f" source {src}"

    print(f"\n  [*] Ejecutando en el router: {cmd}")
    print("  [*] Puede tardar hasta 60 segundos...")
    print("-" * 44)
    out = send_long(channel, cmd)
    print(out)
    print("-" * 44)
    log_action("TRACEROUTE", f"{host}")


def conectividad_tcp_probe(channel):
    """Prueba de conectividad TCP desde el router usando telnet al puerto."""
    print("\n  == TCP PROBE DESDE EL ROUTER ==")
    print("  Usa 'telnet host puerto' para verificar si un puerto esta abierto.")
    print("  Funciona desde el router sin necesidad de herramientas adicionales.")
    host = input("  Host o IP: ").strip()
    port = input("  Puerto TCP: ").strip()

    cmd = f"telnet {host} {port}"
    print(f"\n  [*] Ejecutando en el router: {cmd}")
    print("  [*] Si conecta, escribe  exit_menu  para volver.")
    print("-" * 44)
    log_action("TCP_PROBE", f"{host}:{port}")

    channel.send(cmd + "\n")
    time.sleep(3)
    out = recv_all(channel, timeout=4)
    _sys.stdout.write(out)
    _sys.stdout.flush()

    if "Connected" in out or "Escape" in out:
        print(f"\n  [OK] Puerto {port} ABIERTO en {host}")
        print("  Escribe  exit_menu  para volver (o Ctrl+] en IOS para salir del telnet)")
        _router_shell_loop(channel)
    elif "Connection refused" in out or "Unable" in out or "%" in out:
        print(f"\n  [!!] Puerto {port} CERRADO o NO ALCANZABLE en {host}")
    else:
        print(f"\n  [?] Respuesta no determinada, modo interactivo:")
        _router_shell_loop(channel)


def conectividad_show_ip_brief(channel):
    """Muestra interfaces y IPs del router (referencia rapida)."""
    print(send_long(channel, "show ip interface brief"))


def conectividad_show_arp(channel):
    """Muestra tabla ARP del router."""
    print(send_long(channel, "show arp"))


def conectividad_show_cdp(channel):
    """Muestra vecinos CDP (dispositivos conectados directamente)."""
    print(send_long(channel, "show cdp neighbors detail"))


def conectividad_menu(channel):
    """Sub-menu de conectividad — todo ejecutado DESDE el router."""
    opciones = [
        ("Ping simple desde el router",                  conectividad_ping_simple),
        ("Ping extendido IOS (interactivo)",             conectividad_ping_extendido),
        ("Ping multiple / Sweep de red",                 conectividad_ping_multiple),
        ("Traceroute desde el router",                   conectividad_traceroute),
        ("TCP Probe via Telnet (verificar puerto)",      conectividad_tcp_probe),
        ("Ver interfaces y IPs (ip interface brief)",    conectividad_show_ip_brief),
        ("Ver tabla ARP",                                conectividad_show_arp),
        ("Ver vecinos CDP",                              conectividad_show_cdp),
    ]
    print("\n  ============================================")
    print("    CONECTIVIDAD / PRUEBAS DE RED")
    print("    (Ejecutado DESDE el router)")
    print("  ============================================")
    for i, (desc, _) in enumerate(opciones, 1):
        print(f"   {i}  {desc}")
    print("   0  Volver")
    print("  ============================================")
    sub = input("  Opcion: ").strip()
    if sub == "0" or not sub.isdigit():
        return
    idx = int(sub) - 1
    if 0 <= idx < len(opciones):
        opciones[idx][1](channel)


# ============================================================
#  MENU
# ============================================================

MENUS = {
    "1": ("Interfaces", [
        ("Configurar Interface (IP + no shutdown)",  configure_interface),
        ("Apagar Interface (shutdown)",               shutdown_interface),
        ("Levantar Interface (no shutdown)",          noshutdown_interface),
        ("Remover IP de Interface",                   remove_ip_interface),
        ("Agregar IP Secundaria",                     configure_secondary_ip),
        ("Configurar Bandwidth",                      configure_interface_bandwidth),
        ("Mostrar Interfaces (brief)",                show_interfaces_brief),
        ("Detalle completo de Interface",             show_interface_detail),
        ("Mostrar todas las Interfaces",              show_interfaces_status),
    ]),
    "2": ("Routing / Tablas", [
        ("Mostrar Tabla de Rutas completa",           show_routes),
        ("Resumen de Tabla de Rutas",                 show_route_summary),
        ("Buscar ruta especifica",                    show_route_specific),
        ("Agregar Ruta Estatica",                     add_static_route),
        ("Eliminar Ruta Estatica",                    delete_static_route),
        ("Eliminar TODAS las Rutas Estaticas [!!!]",  flush_all_static_routes),
        ("Agregar Ruta Default",                      add_default_route),
        ("Eliminar Ruta Default [!]",                 delete_default_route),
        ("Mostrar Tabla ARP",                         show_arp_table),
        ("Limpiar Tabla ARP [!]",                     clear_arp_table),
    ]),
    "3": ("OSPF", [
        ("Configurar OSPF",                           configure_ospf),
        ("Eliminar proceso OSPF [!]",                 disable_ospf),
        ("Ver Vecinos OSPF",                          show_ospf_neighbors),
        ("Ver Base de Datos OSPF",                    show_ospf_database),
        ("Configurar Autenticacion MD5",              configure_ospf_auth),
        ("Configurar Interface Pasiva",               configure_ospf_passive),
    ]),
    "4": ("EIGRP", [
        ("Configurar EIGRP",                          configure_eigrp),
        ("Eliminar EIGRP [!]",                        disable_eigrp),
        ("Ver Vecinos EIGRP",                         show_eigrp_neighbors),
        ("Ver Topologia EIGRP",                       show_eigrp_topology),
    ]),
    "5": ("RIP", [
        ("Configurar RIP",                            configure_rip),
        ("Eliminar RIP [!]",                          disable_rip),
    ]),
    "6": ("BGP", [
        ("Configurar vecino BGP",                     configure_bgp),
        ("Eliminar proceso BGP [!!!]",                disable_bgp),
        ("Resumen BGP",                               show_bgp_summary),
        ("Ver tabla BGP completa",                    show_bgp_table),
    ]),
    "7": ("ACL", [
        ("Crear ACL Standard (1-99)",                 create_acl_standard),
        ("Crear ACL Extendida (100-199)",             create_acl_extended),
        ("Eliminar ACL [!]",                          delete_acl),
        ("Aplicar ACL a Interface",                   apply_acl_interface),
        ("Mostrar ACLs",                              show_acls),
    ]),
    "8": ("NAT / PAT", [
        ("Configurar NAT Overload (PAT)",             configure_nat_overload),
        ("Configurar NAT Estatico",                   configure_nat_static),
        ("Limpiar Traducciones NAT dinamicas [!]",    clear_nat_translations),
        ("Ver Traducciones NAT",                      show_nat_translations),
        ("Ver Estadisticas NAT",                      show_nat_stats),
    ]),
    "9": ("DHCP", [
        ("Crear Pool DHCP",                           configure_dhcp_pool),
        ("Excluir Rango de IPs",                      exclude_dhcp_range),
        ("Eliminar Pool DHCP [!]",                    delete_dhcp_pool),
        ("Ver Bindings DHCP",                         show_dhcp_bindings),
        ("Ver Pools DHCP",                            show_dhcp_pool),
        ("Limpiar Bindings DHCP [!]",                 clear_dhcp_bindings),
    ]),
    "10": ("Usuarios y Seguridad", [
        ("Crear Usuario Local",                       create_local_user),
        ("Eliminar Usuario [!]",                      delete_local_user),
        ("Cambiar Enable Secret [!]",                 change_enable_secret),
        ("Configurar SSH v2",                         configure_ssh),
        ("Password de Consola",                       configure_console_password),
        ("Password VTY",                              configure_vty_password),
        ("Ver usuarios conectados",                   show_users),
    ]),
    "11": ("Sistema / Global", [
        ("Cambiar Hostname",                          set_hostname),
        ("Configurar NTP",                            configure_ntp),
        ("Configurar Syslog",                         configure_syslog),
        ("Configurar SNMP",                           configure_snmp),
        ("Eliminar Community SNMP",                   delete_snmp),
        ("Configurar Banner MOTD",                    configure_banner),
        ("Ver Running-Config",                        show_running_config),
        ("Ver Startup-Config",                        show_startup_config),
        ("Guardar Configuracion",                     save_config),
        ("Ver CDP Neighbors",                         show_cdp_neighbors),
        ("Ver CPU",                                   show_processes_cpu),
        ("Ver Memoria",                               show_memory),
        ("Ver Log",                                   show_log),
        ("Ver Reloj",                                 show_clock),
        ("Configurar IP SLA",                         configure_ip_sla),
        ("Borrar Startup-Config [!!!]",               erase_startup_config),
        ("Recargar Router [!!!]",                     reload_device),
        ("Ver Log de Sesion Cifrado",                  dump_log),
    ]),
    "12": ("Tuneles SSH / Conexion Remota", [
        ("SSH / Shell desde el router",               ssh_tunel_menu),
        ("Nueva conexion a otro dispositivo",         reconectar_desde_menu),
    ]),
    "13": ("Conectividad / Pruebas de Red", [
        ("Abrir menu de conectividad",              conectividad_menu),
    ]),
    "0": ("Salir", None),
}


def print_main_menu():
    print("\n" + "="*44)
    print("        ROUTER MANAGER v3.0 – Cisco IOS")
    print("="*44)
    for k, v in MENUS.items():
        label = v[0]
        print(f"   {k:>2}  {label}")
    print("="*44)


def print_sub_menu(cat_name, items):
    print(f"\n{'='*44}")
    print(f"   {cat_name}")
    print(f"{'='*44}")
    for i, (desc, _) in enumerate(items, 1):
        print(f"   {i:>2}  {desc}")
    print(f"{'='*44}")
    print(f"    0  << Volver al menu principal")
    print(f"   00  Salir del programa")
    print(f"{'='*44}")


def ask_exit_confirm():
    """Pide confirmacion antes de salir."""
    print("\n  +----------------------------------+")
    print("  |   ¿Seguro que desea salir?        |")
    print("  |   Se cerrara la sesion SSH.        |")
    print("  +----------------------------------+")
    r = input("  Confirmar salida (s/n): ").strip().lower()
    return r == "s"


def run_menu(channel):
    """Muestra el menu principal. Retorna False solo cuando el usuario confirma salir."""
    print_main_menu()
    cat = input("  Categoria: ").strip()

    # Salir con confirmacion
    if cat == "0":
        if ask_exit_confirm():
            return False
        return True

    if cat not in MENUS or MENUS[cat][1] is None:
        print("  Opcion invalida.")
        return True

    # Submenu – loop hasta que el usuario elija volver o salir
    cat_name, items = MENUS[cat]
    while True:
        print_sub_menu(cat_name, items)
        sub = input("  Opcion: ").strip()

        if sub == "0":
            # Volver al menu principal
            return True

        if sub == "00":
            # Salir con confirmacion desde el submenu
            if ask_exit_confirm():
                return False
            continue

        if not sub.isdigit() or not (1 <= int(sub) <= len(items)):
            print("  Opcion invalida.")
            continue

        _, func = items[int(sub) - 1]
        log_action("MENU", f"{cat_name} > {items[int(sub)-1][0]}")
        func(channel)
        # Despues de ejecutar una funcion, vuelve al submenu automaticamente

    return True


def main():
    print("=" * 44)
    print("   ROUTER MANAGER v3.0  –  Cisco IOS")
    print("=" * 44)
    if not _CRYPTO_OK:
        print("  [!] AVISO: modulo 'cryptography' no instalado.")
        print("      Instalar con: pip install cryptography")
        print("      El log cifrado no estara disponible.")
    else:
        print(f"  [*] Log cifrado activo -> {_LOG_FILE}")
    host            = input("  IP del Router   : ")
    username        = input("  Usuario         : ")
    password        = input("  Password         : ")
    enable_password = input("  Enable Password  : ")
    print("  Metodo de conexion:")
    print("   1  SSH (recomendado)")
    print("   2  Telnet")
    m = input("  Opcion (Enter=SSH): ").strip()
    metodo = "telnet" if m == "2" else "ssh"
    telnet_port = 23
    if metodo == "telnet":
        p = input("  Puerto Telnet (Enter=23): ").strip()
        telnet_port = int(p) if p.isdigit() else 23

    transport_or_client, channel, metodo_ok = conectar(
        host, username, password, enable_password,
        metodo_preferido=metodo, telnet_port=telnet_port,
    )
    detect_device(channel)

    while run_menu(channel):
        pass

    log_action("SESSION", "Sesion cerrada por el usuario")
    print("\n[*] Cerrando conexion...")
    try:
        channel.close()
    except Exception:
        pass
    try:
        # funciona tanto con SSHClient como con Transport directo
        if hasattr(transport_or_client, 'close'):
            transport_or_client.close()
    except Exception:
        pass
    print("[*] Listo.")


if __name__ == "__main__":
    main()
