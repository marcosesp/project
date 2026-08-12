#!/bin/bash
# Forzamos al shell a vaciar el búfer de salida inmediatamente
export PYTHONUNBUFFERED=1

# Ejecutamos dnf con stdbuf para forzar el volcado línea por línea
stdbuf -oL -eL dnf -y update
