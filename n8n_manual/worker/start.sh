#!/bin/sh
set -eu

# Preparar las claves del servidor SSH que no existan
ssh-keygen -A

# Preparar la carpeta de autenticación del usuario ti1
install -d -m 700 -o ti1 -g ti1 /home/ti1/.ssh

# Colocar la clave publica autorizada
install -m 600 -o ti1 -g ti1 \
    /run/ti1.pub \
    /home/ti1/.ssh/authorized_keys

# Permitir que ti1 escriba en la carpeta de evidencias
chown ti1:ti1 /home/ti1/evidence

# Asignar una contraseña aleatoria a la cuenta
# El acceso SSH mediante contraseña estará deshabilitado
python3 -c 'import secrets; print("ti1:" + secrets.token_hex(32))' \
    | chpasswd

# Iniciar el servidor SSH
exec /usr/sbin/sshd -D -e \
    -o PasswordAuthentication=no \
    -o KbdInteractiveAuthentication=no \
    -o PermitRootLogin=no \
    -o AllowUsers=ti1