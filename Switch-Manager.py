#!/usr/bin/env python3
# ============================================================
#  SWITCH MANAGER v3.0  –  Cisco IOS / IOS-XE
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
            if re.search(r'[>#]\s*$', output):
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
    """Para comandos con mucha salida. Desactiva paginacion, ejecuta y restaura.
    Maneja el caso donde el canal quedo en modo usuario tras una sesion interactiva."""
    try:
        channel.send("\n")
        time.sleep(0.5)
        probe = recv_all(channel, timeout=1)
    except Exception as e:
        raise OSError(f"Canal SSH cerrado: {e}")
    if re.search(r"\w+>\s*$", probe):
        channel.send("enable\n")
        time.sleep(0.5)
        recv_all(channel, timeout=1)
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
    elif "NX-OS" in raw:
        ios_type = "NX-OS"

    # modelo – patrones para Catalyst, Nexus, etc.
    patterns = [
        r'[Cc]isco\s+(WS-C[\w\-]+)',           # WS-C3560, WS-C2960
        r'[Cc]isco\s+(C[\d]{3,4}[\w\-]*)',     # C3750, C2960
        r'[Cc]isco\s+(N[\d]K-[\w\-]+)',         # N5K, N7K Nexus
        r'[Cc]isco\s+([A-Z]{2,5}\d[\w\-]+)',   # ASR, ISR, etc.
        r'[Cc]isco\s+([\w]{2,}-[\w]+-[\w]+)',  # genérico modelo con guiones
        r'[Cc]isco\s+(\d{3,4}[\w\-]*)',        # 3750, 2960
    ]
    for pat in patterns:
        m = re.search(pat, raw)
        if m:
            model = m.group(1)
            break

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
#  VLANs
# ============================================================

def create_vlan(channel):
    vlan = input("  VLAN ID: ")
    if not vlan.isdigit():
        print("  ID invalido.")
        return
    name = input(f"  Nombre (Enter = VLAN_{vlan}): ").strip() or f"VLAN_{vlan}"
    send(channel, "configure terminal")
    out = send(channel, f"vlan {vlan}")
    if check_error(out):
        send(channel, "end")
        return
    send(channel, f"name {name}")
    send(channel, "end")
    send(channel, "write memory", 3)
    print(f"  [OK] VLAN {vlan} ({name}) creada.")

def delete_vlan(channel):
    vlan = input("  VLAN ID a borrar: ")
    if not confirm(f"  [!] ¿Eliminar VLAN {vlan}? Desconectara los puertos asignados. (s/n): "):
        return
    send(channel, "configure terminal")
    out = send(channel, f"no vlan {vlan}")
    if check_error(out):
        send(channel, "end")
        return
    send(channel, "end")
    send(channel, "write memory", 3)
    print(f"  [OK] VLAN {vlan} eliminada.")

def delete_all_vlans(channel):
    if not confirm("  [!!!] Eliminar TODAS las VLANs (excepto la 1). ¿Continuar? (s/n): "):
        return
    if not confirm("  [!!!] ULTIMA confirmacion. ¿Seguro? (s/n): "):
        return
    raw   = send_long(channel, "show vlan brief")
    vlans = re.findall(r'^(\d+)\s+\S', raw, re.MULTILINE)
    send(channel, "configure terminal")
    deleted = 0
    for v in vlans:
        if v not in ["1", "1002", "1003", "1004", "1005"]:
            send(channel, f"no vlan {v}", 0.5)
            deleted += 1
    send(channel, "end")
    send(channel, "write memory", 3)
    print(f"  [OK] {deleted} VLAN(s) eliminadas.")

def rename_vlan(channel):
    vlan = input("  VLAN ID: ")
    name = input("  Nuevo nombre: ")
    send(channel, "configure terminal")
    send(channel, f"vlan {vlan}")
    check_error(send(channel, f"name {name}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] VLAN renombrada.")

def show_vlans(channel):
    print(send_long(channel, "show vlan brief"))

def show_vlan_detail(channel):
    vlan = input("  VLAN ID: ")
    print(send_long(channel, f"show vlan id {vlan}"))

def assign_vlan_access(channel):
    iface = input("  Interface (ej: fa0/1 o g0/1): ")
    vlan  = input("  VLAN ID: ")
    send(channel, "configure terminal")
    send(channel, f"interface {iface}")
    send(channel, "switchport mode access")
    check_error(send(channel, f"switchport access vlan {vlan}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Interface configurada como access.")

def remove_vlan_from_interface(channel):
    iface = input("  Interface: ")
    send(channel, "configure terminal")
    send(channel, f"interface {iface}")
    check_error(send(channel, "no switchport access vlan"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] VLAN removida de interface.")

def show_interfaces_switchport(channel):
    iface = input("  Interface (Enter para todas): ").strip()
    if iface:
        print(send_long(channel, f"show interfaces {iface} switchport"))
    else:
        print(send_long(channel, "show interfaces switchport"))

# ============================================================
#  TRUNK
# ============================================================

def configure_trunk(channel):
    iface = input("  Interface trunk (ej: g0/1): ")
    send(channel, "configure terminal")
    send(channel, f"interface {iface}")
    # intentar encapsulation dot1q (puede fallar en switches que solo soportan dot1q)
    out = send(channel, "switchport trunk encapsulation dot1q")
    # no check_error aqui porque en algunos switches no es necesario
    check_error(send(channel, "switchport mode trunk"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print(f"  [OK] Interface {iface} configurada como trunk.")

def configure_trunk_allowed(channel):
    iface = input("  Interface trunk: ")
    vlans = input("  VLANs permitidas (ej: 10,20,30 o 10-50): ")
    send(channel, "configure terminal")
    send(channel, f"interface {iface}")
    check_error(send(channel, f"switchport trunk allowed vlan {vlans}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] VLANs permitidas actualizadas.")

def add_trunk_vlans(channel):
    iface = input("  Interface trunk: ")
    vlans = input("  VLANs a AGREGAR: ")
    send(channel, "configure terminal")
    send(channel, f"interface {iface}")
    check_error(send(channel, f"switchport trunk allowed vlan add {vlans}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] VLANs agregadas al trunk.")

def remove_trunk_vlans(channel):
    iface = input("  Interface trunk: ")
    vlans = input("  VLANs a REMOVER del trunk: ")
    if not confirm(f"  [!] ¿Remover VLANs {vlans} del trunk {iface}? (s/n): "):
        return
    send(channel, "configure terminal")
    send(channel, f"interface {iface}")
    check_error(send(channel, f"switchport trunk allowed vlan remove {vlans}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] VLANs removidas.")

def configure_native_vlan(channel):
    iface = input("  Interface trunk: ")
    vlan  = input("  VLAN nativa: ")
    send(channel, "configure terminal")
    send(channel, f"interface {iface}")
    check_error(send(channel, f"switchport trunk native vlan {vlan}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] VLAN nativa configurada.")

def show_trunk(channel):
    print(send_long(channel, "show interfaces trunk"))

# ============================================================
#  VTP
# ============================================================

def show_vtp_status(channel):
    print(send_long(channel, "show vtp status"))

def configure_vtp_server(channel):
    domain  = input("  Dominio VTP: ")
    version = input("  Version VTP (1/2/3, Enter=2): ").strip() or "2"
    pwd     = input("  Password VTP (Enter omitir): ").strip()
    send(channel, "configure terminal")
    check_error(send(channel, f"vtp domain {domain}"))
    check_error(send(channel, f"vtp version {version}"))
    check_error(send(channel, "vtp mode server"))
    if pwd:
        check_error(send(channel, f"vtp password {pwd}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print(f"  [OK] VTP Server – dominio '{domain}' version {version}.")

def configure_vtp_client(channel):
    domain = input("  Dominio VTP: ")
    pwd    = input("  Password VTP (Enter omitir): ").strip()
    send(channel, "configure terminal")
    check_error(send(channel, f"vtp domain {domain}"))
    check_error(send(channel, "vtp mode client"))
    if pwd:
        check_error(send(channel, f"vtp password {pwd}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print(f"  [OK] VTP Client – dominio '{domain}'.")

def configure_vtp_transparent(channel):
    send(channel, "configure terminal")
    check_error(send(channel, "vtp mode transparent"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] VTP Transparent configurado.")

def configure_vtp_off(channel):
    if not confirm("  [!] ¿Desactivar VTP (vtp mode off, requiere VTPv3)? (s/n): "):
        return
    send(channel, "configure terminal")
    check_error(send(channel, "vtp mode off"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] VTP desactivado.")

def change_vtp_password(channel):
    pwd = input("  Nuevo password VTP: ")
    send(channel, "configure terminal")
    check_error(send(channel, f"vtp password {pwd}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Password VTP cambiado.")

def delete_vtp_password(channel):
    if not confirm("  [!] ¿Eliminar password VTP? (s/n): "):
        return
    send(channel, "configure terminal")
    check_error(send(channel, "no vtp password"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Password VTP eliminado.")

def change_vtp_domain(channel):
    domain = input("  Nuevo dominio VTP: ")
    if not confirm(f"  [!] Cambiar dominio a '{domain}' resetea el revision number. ¿Continuar? (s/n): "):
        return
    send(channel, "configure terminal")
    check_error(send(channel, f"vtp domain {domain}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Dominio VTP cambiado.")

def reset_vtp_revision(channel):
    """Truco para resetear revision number: transparent -> modo original."""
    mode = input("  Modo VTP actual (server/client): ").strip()
    if not confirm("  [!] ¿Resetear revision number VTP? (s/n): "):
        return
    send(channel, "configure terminal")
    check_error(send(channel, "vtp mode transparent"))
    check_error(send(channel, f"vtp mode {mode}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Revision number VTP reseteado a 0.")

def show_vtp_counters(channel):
    print(send_long(channel, "show vtp counters"))

# ============================================================
#  SPANNING TREE (STP)
# ============================================================

def show_stp(channel):
    vlan = input("  VLAN ID (Enter para todas): ").strip()
    if vlan:
        print(send_long(channel, f"show spanning-tree vlan {vlan}"))
    else:
        print(send_long(channel, "show spanning-tree"))

def show_stp_detail(channel):
    print(send_long(channel, "show spanning-tree detail"))

def configure_stp_mode(channel):
    print("  Modos disponibles: pvst | rapid-pvst | mst")
    mode = input("  Modo STP: ")
    if not confirm(f"  [!] ¿Cambiar STP a '{mode}'? Puede causar reconvergencia. (s/n): "):
        return
    send(channel, "configure terminal")
    check_error(send(channel, f"spanning-tree mode {mode}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Modo STP cambiado.")

def configure_root_primary(channel):
    vlan = input("  VLAN ID (Enter = todas): ").strip()
    send(channel, "configure terminal")
    if vlan:
        check_error(send(channel, f"spanning-tree vlan {vlan} root primary"))
    else:
        check_error(send(channel, "spanning-tree vlan 1-4094 root primary"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Switch configurado como Root Bridge primario.")

def configure_root_secondary(channel):
    vlan = input("  VLAN ID: ")
    send(channel, "configure terminal")
    check_error(send(channel, f"spanning-tree vlan {vlan} root secondary"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Switch configurado como Root Bridge secundario.")

def configure_portfast(channel):
    iface = input("  Interface: ")
    send(channel, "configure terminal")
    send(channel, f"interface {iface}")
    check_error(send(channel, "spanning-tree portfast"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] PortFast habilitado.")

def configure_bpduguard(channel):
    iface = input("  Interface: ")
    send(channel, "configure terminal")
    send(channel, f"interface {iface}")
    check_error(send(channel, "spanning-tree bpduguard enable"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] BPDU Guard habilitado.")

def configure_portfast_bpduguard_global(channel):
    send(channel, "configure terminal")
    check_error(send(channel, "spanning-tree portfast default"))
    check_error(send(channel, "spanning-tree portfast bpduguard default"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] PortFast + BPDU Guard habilitados globalmente.")

def disable_stp_vlan(channel):
    vlan = input("  VLAN ID para deshabilitar STP: ")
    if not confirm(f"  [!!!] PELIGRO: deshabilitar STP en VLAN {vlan} puede causar loops. ¿Continuar? (s/n): "):
        return
    send(channel, "configure terminal")
    check_error(send(channel, f"no spanning-tree vlan {vlan}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print(f"  [OK] STP deshabilitado en VLAN {vlan}. Cuidado con loops.")

# ============================================================
#  PORT SECURITY
# ============================================================

def configure_port_security(channel):
    iface   = input("  Interface: ")
    max_mac = input("  Maximo de MACs (Enter=1): ").strip() or "1"
    action  = input("  Violacion (shutdown/restrict/protect, Enter=shutdown): ").strip() or "shutdown"
    sticky  = input("  ¿Habilitar sticky MAC? (s/n): ").strip().lower() == 's'
    send(channel, "configure terminal")
    send(channel, f"interface {iface}")
    send(channel, "switchport mode access")
    check_error(send(channel, "switchport port-security"))
    check_error(send(channel, f"switchport port-security maximum {max_mac}"))
    check_error(send(channel, f"switchport port-security violation {action}"))
    if sticky:
        check_error(send(channel, "switchport port-security mac-address sticky"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Port Security configurado.")

def add_static_mac_port_security(channel):
    iface = input("  Interface: ")
    mac   = input("  MAC (formato xxxx.xxxx.xxxx): ")
    vlan  = input("  VLAN ID: ")
    send(channel, "configure terminal")
    send(channel, f"interface {iface}")
    check_error(send(channel, f"switchport port-security mac-address {mac} vlan {vlan}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] MAC estatica agregada.")

def show_port_security(channel):
    iface = input("  Interface (Enter para todas): ").strip()
    if iface:
        print(send_long(channel, f"show port-security interface {iface}"))
    else:
        print(send_long(channel, "show port-security"))

def clear_port_security_violation(channel):
    iface = input("  Interface en err-disabled: ")
    send(channel, "configure terminal")
    send(channel, f"interface {iface}")
    check_error(send(channel, "shutdown"))
    time.sleep(1)
    check_error(send(channel, "no shutdown"))
    send(channel, "end")
    print("  [OK] Puerto recuperado.")

def disable_port_security(channel):
    iface = input("  Interface: ")
    send(channel, "configure terminal")
    send(channel, f"interface {iface}")
    check_error(send(channel, "no switchport port-security"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Port Security desactivado.")

# ============================================================
#  ETHERCHANNEL
# ============================================================

def configure_etherchannel_lacp(channel):
    raw    = input("  Interfaces separadas por coma (ej: g0/1,g0/2): ")
    ifaces = [i.strip() for i in raw.split(",")]
    group  = input("  Numero de grupo: ")
    mode   = input("  Modo LACP (active/passive): ")
    send(channel, "configure terminal")
    for iface in ifaces:
        send(channel, f"interface {iface}")
        check_error(send(channel, f"channel-group {group} mode {mode}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print(f"  [OK] EtherChannel LACP grupo {group} configurado.")

def configure_etherchannel_pagp(channel):
    raw    = input("  Interfaces separadas por coma: ")
    ifaces = [i.strip() for i in raw.split(",")]
    group  = input("  Numero de grupo: ")
    mode   = input("  Modo PAgP (desirable/auto): ")
    send(channel, "configure terminal")
    for iface in ifaces:
        send(channel, f"interface {iface}")
        check_error(send(channel, f"channel-group {group} mode {mode}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print(f"  [OK] EtherChannel PAgP grupo {group} configurado.")

def configure_etherchannel_on(channel):
    raw    = input("  Interfaces separadas por coma: ")
    ifaces = [i.strip() for i in raw.split(",")]
    group  = input("  Numero de grupo: ")
    send(channel, "configure terminal")
    for iface in ifaces:
        send(channel, f"interface {iface}")
        check_error(send(channel, f"channel-group {group} mode on"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print(f"  [OK] EtherChannel forzado (on) grupo {group}.")

def delete_etherchannel(channel):
    group = input("  Numero de grupo a eliminar: ")
    if not confirm(f"  [!] ¿Eliminar port-channel {group}? (s/n): "):
        return
    send(channel, "configure terminal")
    check_error(send(channel, f"no interface port-channel {group}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] EtherChannel eliminado.")

def show_etherchannel(channel):
    print(send_long(channel, "show etherchannel summary"))

def show_etherchannel_detail(channel):
    group = input("  Numero de grupo: ")
    print(send_long(channel, f"show etherchannel {group} detail"))

# ============================================================
#  L3 SWITCH – SVI / ROUTING
# ============================================================

def configure_svi(channel):
    vlan = input("  VLAN ID para SVI: ")
    ip   = input("  IP: ")
    mask = input("  Mascara: ")
    desc = input("  Descripcion (Enter omitir): ").strip()
    send(channel, "configure terminal")
    send(channel, f"interface vlan {vlan}")
    if desc:
        send(channel, f"description {desc}")
    check_error(send(channel, f"ip address {ip} {mask}"))
    check_error(send(channel, "no shutdown"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print(f"  [OK] SVI VLAN {vlan} configurada.")

def delete_svi(channel):
    vlan = input("  VLAN ID del SVI a eliminar: ")
    if not confirm(f"  [!] ¿Eliminar SVI VLAN {vlan}? (s/n): "):
        return
    send(channel, "configure terminal")
    check_error(send(channel, f"no interface vlan {vlan}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] SVI eliminada.")

def enable_ip_routing(channel):
    send(channel, "configure terminal")
    check_error(send(channel, "ip routing"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] IP Routing habilitado.")

def disable_ip_routing(channel):
    if not confirm("  [!] ¿Deshabilitar IP routing? El switch dejara de rutear. (s/n): "):
        return
    send(channel, "configure terminal")
    check_error(send(channel, "no ip routing"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] IP Routing deshabilitado.")

def add_static_route(channel):
    dest    = input("  Red destino: ")
    mask    = input("  Mascara: ")
    nexthop = input("  Next-hop: ")
    send(channel, "configure terminal")
    check_error(send(channel, f"ip route {dest} {mask} {nexthop}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Ruta estatica agregada.")

def show_ip_route(channel):
    print(send_long(channel, "show ip route"))

def show_interfaces_brief(channel):
    print(send_long(channel, "show ip interface brief"))

# ============================================================
#  TABLA MAC
# ============================================================

def show_mac_table(channel):
    vlan = input("  VLAN (Enter para todas): ").strip()
    if vlan:
        print(send_long(channel, f"show mac address-table vlan {vlan}"))
    else:
        print(send_long(channel, "show mac address-table"))

def show_mac_by_address(channel):
    mac = input("  MAC address (formato xxxx.xxxx.xxxx): ")
    print(send_long(channel, f"show mac address-table address {mac}"))

def show_mac_by_interface(channel):
    iface = input("  Interface: ")
    print(send_long(channel, f"show mac address-table interface {iface}"))

def clear_mac_table(channel):
    if not confirm("  [!] ¿Limpiar tabla MAC dinamica? (s/n): "):
        return
    send(channel, "clear mac address-table dynamic", 2)
    print("  [OK] Tabla MAC limpiada.")

def show_mac_count(channel):
    print(send_long(channel, "show mac address-table count"))

# ============================================================
#  USUARIOS Y SEGURIDAD
# ============================================================

def create_local_user(channel):
    user = input("  Nuevo usuario: ")
    priv = input("  Privilegio (0-15): ")
    pwd  = input("  Password: ")
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
    pwd = input("  Nuevo enable secret: ")
    send(channel, "configure terminal")
    check_error(send(channel, f"enable secret {pwd}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Enable secret cambiado.")

def configure_ssh(channel):
    domain = input("  Dominio (ej: empresa.local): ")
    bits   = input("  Bits RSA (1024/2048): ")
    send(channel, "configure terminal")
    check_error(send(channel, f"ip domain-name {domain}"))
    out = send(channel, f"crypto key generate rsa modulus {bits}", 5)
    if "How many bits" in out:
        channel.send(f"{bits}\n")
        time.sleep(3)
        recv_all(channel)
    check_error(send(channel, "ip ssh version 2"))
    send(channel, "line vty 0 15")
    check_error(send(channel, "transport input ssh"))
    check_error(send(channel, "login local"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] SSH v2 configurado.")

def configure_console_password(channel):
    pwd = input("  Password consola: ")
    send(channel, "configure terminal")
    send(channel, "line console 0")
    check_error(send(channel, f"password {pwd}"))
    check_error(send(channel, "login"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] Password consola configurado.")

def show_users(channel):
    print(send_long(channel, "show users"))

# ============================================================
#  SISTEMA / GLOBAL
# ============================================================

def configure_management_ip(channel):
    vlan    = input("  VLAN de management (Enter=1): ").strip() or "1"
    ip      = input("  IP de management: ")
    mask    = input("  Mascara: ")
    gateway = input("  Gateway (Enter omitir): ").strip()
    send(channel, "configure terminal")
    send(channel, f"interface vlan {vlan}")
    check_error(send(channel, f"ip address {ip} {mask}"))
    check_error(send(channel, "no shutdown"))
    if gateway:
        check_error(send(channel, f"ip default-gateway {gateway}"))
    send(channel, "end")
    send(channel, "write memory", 3)
    print("  [OK] IP de management configurada.")

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
    level  = input("  Nivel (Enter=informational): ").strip() or "informational"
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

def show_interfaces_status(channel):
    print(send_long(channel, "show interfaces status"))

def erase_startup_config(channel):
    if not confirm("  [!!!] PELIGRO EXTREMO: borrara startup-config. ¿Continuar? (s/n): "):
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
    if not confirm("  [!!!] PELIGRO: reiniciara el switch. ¿Continuar? (s/n): "):
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
    "1": ("VLANs", [
        ("Crear VLAN",                                create_vlan),
        ("Eliminar VLAN [!]",                         delete_vlan),
        ("Eliminar TODAS las VLANs [!!!]",            delete_all_vlans),
        ("Renombrar VLAN",                            rename_vlan),
        ("Asignar VLAN a Interface (access)",         assign_vlan_access),
        ("Remover VLAN de Interface",                 remove_vlan_from_interface),
        ("Mostrar VLANs (brief)",                     show_vlans),
        ("Detalle de una VLAN",                       show_vlan_detail),
        ("Ver switchport de Interface",               show_interfaces_switchport),
    ]),
    "2": ("Trunk", [
        ("Configurar Trunk",                          configure_trunk),
        ("Configurar VLANs Permitidas (set)",         configure_trunk_allowed),
        ("Agregar VLANs al Trunk",                    add_trunk_vlans),
        ("Remover VLANs del Trunk [!]",               remove_trunk_vlans),
        ("Configurar VLAN Nativa",                    configure_native_vlan),
        ("Ver Trunks activos",                        show_trunk),
    ]),
    "3": ("VTP", [
        ("Ver Estado VTP",                            show_vtp_status),
        ("Configurar como VTP Server",                configure_vtp_server),
        ("Configurar como VTP Client",                configure_vtp_client),
        ("Configurar como VTP Transparent",           configure_vtp_transparent),
        ("Desactivar VTP (mode off) [!]",             configure_vtp_off),
        ("Cambiar Password VTP",                      change_vtp_password),
        ("Eliminar Password VTP [!]",                 delete_vtp_password),
        ("Cambiar Dominio VTP [!]",                   change_vtp_domain),
        ("Resetear Revision Number VTP [!]",          reset_vtp_revision),
        ("Ver Contadores VTP",                        show_vtp_counters),
    ]),
    "4": ("Spanning Tree (STP)", [
        ("Ver STP",                                   show_stp),
        ("Ver STP detallado",                         show_stp_detail),
        ("Cambiar Modo STP [!]",                      configure_stp_mode),
        ("Configurar Root Bridge Primario",           configure_root_primary),
        ("Configurar Root Bridge Secundario",         configure_root_secondary),
        ("Habilitar PortFast en Interface",           configure_portfast),
        ("Habilitar BPDU Guard en Interface",         configure_bpduguard),
        ("PortFast + BPDU Guard Global",              configure_portfast_bpduguard_global),
        ("Deshabilitar STP en VLAN [!!!]",            disable_stp_vlan),
    ]),
    "5": ("Port Security", [
        ("Configurar Port Security",                  configure_port_security),
        ("Agregar MAC estatica",                      add_static_mac_port_security),
        ("Ver Port Security",                         show_port_security),
        ("Recuperar Puerto err-disabled",             clear_port_security_violation),
        ("Desactivar Port Security",                  disable_port_security),
    ]),
    "6": ("EtherChannel / LAG", [
        ("Configurar EtherChannel LACP",              configure_etherchannel_lacp),
        ("Configurar EtherChannel PAgP",              configure_etherchannel_pagp),
        ("Configurar EtherChannel forzado (on)",      configure_etherchannel_on),
        ("Eliminar Port-Channel [!]",                 delete_etherchannel),
        ("Ver EtherChannel (summary)",                show_etherchannel),
        ("Ver EtherChannel (detalle)",                show_etherchannel_detail),
    ]),
    "7": ("L3 / Routing (switches capa 3)", [
        ("Configurar SVI (interface VLAN)",           configure_svi),
        ("Eliminar SVI [!]",                          delete_svi),
        ("Habilitar IP Routing",                      enable_ip_routing),
        ("Deshabilitar IP Routing [!]",               disable_ip_routing),
        ("Agregar Ruta Estatica",                     add_static_route),
        ("Ver Tabla de Rutas",                        show_ip_route),
        ("Ver Interfaces (brief)",                    show_interfaces_brief),
        ("Configurar IP de Management",               configure_management_ip),
    ]),
    "8": ("Tabla MAC", [
        ("Ver Tabla MAC",                             show_mac_table),
        ("Buscar por MAC address",                    show_mac_by_address),
        ("Buscar MACs por Interface",                 show_mac_by_interface),
        ("Ver Conteo de MACs",                        show_mac_count),
        ("Limpiar Tabla MAC dinamica [!]",            clear_mac_table),
    ]),
    "9": ("Usuarios y Seguridad", [
        ("Crear Usuario Local",                       create_local_user),
        ("Eliminar Usuario [!]",                      delete_local_user),
        ("Cambiar Enable Secret [!]",                 change_enable_secret),
        ("Configurar SSH v2",                         configure_ssh),
        ("Password de Consola",                       configure_console_password),
        ("Ver usuarios conectados",                   show_users),
    ]),
    "10": ("Sistema / Global", [
        ("Configurar IP de Management",               configure_management_ip),
        ("Cambiar Hostname",                          set_hostname),
        ("Configurar NTP",                            configure_ntp),
        ("Configurar Syslog",                         configure_syslog),
        ("Configurar SNMP",                           configure_snmp),
        ("Configurar Banner MOTD",                    configure_banner),
        ("Ver Running-Config",                        show_running_config),
        ("Ver Startup-Config",                        show_startup_config),
        ("Guardar Configuracion",                     save_config),
        ("Ver CDP Neighbors",                         show_cdp_neighbors),
        ("Ver Estado de Interfaces",                  show_interfaces_status),
        ("Ver CPU",                                   show_processes_cpu),
        ("Ver Memoria",                               show_memory),
        ("Ver Log",                                   show_log),
        ("Ver Reloj",                                 show_clock),
        ("Borrar Startup-Config [!!!]",               erase_startup_config),
        ("Recargar Switch [!!!]",                     reload_device),
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
    print("\n" + "="*46)
    print("       SWITCH MANAGER v3.0 – Cisco IOS/XE")
    print("="*46)
    for k, v in MENUS.items():
        print(f"   {k:>2}  {v[0]}")
    print("="*46)


def print_sub_menu(cat_name, items):
    print(f"\n{'='*46}")
    print(f"   {cat_name}")
    print(f"{'='*46}")
    for i, (desc, _) in enumerate(items, 1):
        print(f"   {i:>2}  {desc}")
    print(f"{'='*46}")
    print(f"    0  << Volver al menu principal")
    print(f"   00  Salir del programa")
    print(f"{'='*46}")


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
    print("=" * 46)
    print("   SWITCH MANAGER v3.0  –  Cisco IOS/XE")
    print("=" * 46)
    if not _CRYPTO_OK:
        print("  [!] AVISO: modulo 'cryptography' no instalado.")
        print("      Instalar con: pip install cryptography")
        print("      El log cifrado no estara disponible.")
    else:
        print(f"  [*] Log cifrado activo -> {_LOG_FILE}")
    host            = input("  IP del Switch   : ")
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
