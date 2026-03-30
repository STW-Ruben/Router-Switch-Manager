## Router & Switch Manager (Python)

### Descripción

Este proyecto es un Router & Switch Manager en Python orientado a dispositivos Cisco IOS. No es un script básico para enviar comandos, sino una herramienta más completa pensada para administrar equipos de red de forma estructurada, automatizada y con cierto enfoque en seguridad.

Permite interactuar con routers y switches manejando detalles reales como prompts, paginación, autenticación y comportamiento del sistema.

### Características Principales

Conexión por SSH y Telnet con fallback automático

Detección de dispositivo (hostname, modelo, versión IOS)

Manejo automático de prompts y paginación

Acceso a modo enable con validación

Sistema de logging cifrado (AES-256)

Shell interactivo directo en el dispositivo

## Funcionalidades

### Networking

Configuración de interfaces (IP, shutdown, secondary, bandwidth)
Rutas estáticas y default
Protocolos: OSPF, EIGRP, RIP, BGP

### Seguridad

ACLs estándar y extendidas

Usuarios locales

Configuración de SSH, consola y VTY

### Servicios

NAT (estático y overload/PAT)

DHCP

SNMP, NTP, Syslog

### Diagnóstico y Monitoreo

Ping (simple, extendido, sweep)

Traceroute

TCP probe (verificación de puertos)

ARP, CDP

CPU, memoria, logs

## Funcionalidad Destacada

El script permite abrir conexiones desde el propio router hacia otros dispositivos (SSH o Telnet).
Esto simula escenarios reales donde el salto se hace dentro de la red, no desde la máquina local.

## Tecnologías Utilizadas

Python 3

Paramiko (SSH)

Socket (Telnet)

Cryptography (AES-256 logging)

## Estado del Proyecto

El proyecto se encuentra en fase beta.

### Pendientes:

Mejor modularización

Separación en archivos

Manejo de excepciones más robusto

Optimización general

Aun así, ya es funcional para múltiples escenarios reales.

##  Instalación

--bash
git clone https://github.com/STW-Ruben/Router-Switch-Manager.git

cd Router-Switch-Manager

pip install paramiko cryptography

python3 Manager.py
