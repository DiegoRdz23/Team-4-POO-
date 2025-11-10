# -*- coding: utf-8 -*-
import re
from datetime import datetime
from io import BytesIO

import bcrypt
import mysql.connector
from flask import Flask, request, render_template, redirect, url_for, session, send_file

# ReportLab (para PDFs)
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.units import cm
from reportlab.pdfgen import canvas

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = "clave_secreta_segura"

# ---------------------- VALIDACIONES ----------------------
def validar_correo(correo: str) -> bool:
    patron = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(patron, correo) is not None

def validar_contrasena(contrasena: str) -> bool:
    if len(contrasena) < 8:
        return False
    if not re.search(r'[A-Z]', contrasena):
        return False
    if not re.search(r'[a-z]', contrasena):
        return False
    if not re.search(r'[0-9]', contrasena):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', contrasena):
        return False
    return True

def obtener_saludo():
    h = datetime.now().hour
    if 6 <= h < 12:
        return "Buenos días"
    elif 12 <= h < 19:
        return "Buenas tardes"
    else:
        return "Buenas noches"

# ---------------------- CONEXIÓN A MYSQL ----------------------
def obtener_conexion():
    return mysql.connector.connect(
        host="127.0.0.1",
        port=3306,
        user="root",
        password="",
        database="empresa",
        autocommit=False,
    )

def tabla_existe(nombre_tabla: str) -> bool:
    """Comprueba si una tabla existe en la base de datos."""
    conn = obtener_conexion()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT COUNT(*) FROM information_schema.tables
            WHERE table_schema = DATABASE() AND table_name = %s
        """, (nombre_tabla,))
        existe = cur.fetchone()[0] > 0
    finally:
        cur.close(); conn.close()
    return existe

# ---------------------- LOGIN ----------------------
@app.route("/")
def index():
    return render_template("P Entrada.html")

@app.route("/login", methods=["POST"])
def login():
    usuario = request.form.get("usuario", "").strip()
    password = request.form.get("password", "").strip()

    if not usuario or not password:
        return render_template("error.html", mensaje="❌ Faltan campos requeridos"), 400
    if not validar_correo(usuario):
        return render_template("error.html", mensaje="❌ Correo inválido"), 400

    # Buscar usuario por correo
    conn = obtener_conexion()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute("SELECT nombre, rol, contrasena FROM usuarios WHERE correo = %s", (usuario,))
        user = cur.fetchone()
    finally:
        cur.close(); conn.close()

    if user:
        if user["contrasena"] and bcrypt.checkpw(password.encode("utf-8"), user["contrasena"].encode("utf-8")):
            session["user_name"] = user["nombre"]
            session["rol"] = user["rol"]
            session["correo"] = usuario  
            return redirect(url_for("menu"))
        else:
            return render_template("error.html", mensaje="❌ Contraseña incorrecta"), 401
    else:
        return render_template("error.html", mensaje="❌ Usuario no encontrado"), 404

# ---------------------- MENÚ PRINCIPAL ----------------------
@app.route("/menu")
def menu():
    user_name = session.get("user_name")
    rol = session.get("rol")
    if not user_name or not rol:
        return redirect(url_for("index"))
    return render_template("menu.html", user_name=user_name, saludo=obtener_saludo(), rol=rol)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# ---------------------- MÓDULO DE USUARIOS ----------------------
@app.route("/usuarios", methods=["GET", "POST"])
def usuarios():
    rol_actual = session.get("rol")
    if rol_actual != "admin":
        return render_template("error.html", mensaje="❌ Acceso denegado: solo el administrador puede gestionar usuarios."), 403

    conexion = obtener_conexion()
    cursor = conexion.cursor(dictionary=True)

    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        correo = request.form.get("correo", "").strip()
        rol = request.form.get("rol", "").strip()

        if not nombre or not correo or not rol:
            cursor.close(); conexion.close()
            return render_template("error.html", mensaje="❌ Faltan datos para registrar el usuario."), 400

        password_hash = bcrypt.hashpw("Temporal123!".encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        cursor.execute(
            "INSERT INTO usuarios (nombre, correo, rol, contrasena) VALUES (%s, %s, %s, %s)",
            (nombre, correo, rol, password_hash),
        )
        conexion.commit()
        cursor.close(); conexion.close()
        return redirect(url_for("usuarios"))

    cursor.execute("SELECT * FROM usuarios ORDER BY nombre;")
    usuarios = cursor.fetchall()
    cursor.close(); conexion.close()

    return render_template("usuarios.html",
                           usuarios=usuarios,
                           rol=rol_actual,
                           saludo=obtener_saludo(),
                           user_name=session.get("user_name"))

@app.route("/eliminar_usuario/<int:usuario_id>", methods=["POST"])
def eliminar_usuario(usuario_id):
    rol_actual = session.get("rol")
    if rol_actual != "admin":
        return render_template("error.html", mensaje="❌ Acceso denegado: solo el administrador puede eliminar usuarios."), 403

    conn = obtener_conexion()
    cur = conn.cursor()
    cur.execute("DELETE FROM usuarios WHERE id = %s", (usuario_id,))
    conn.commit()
    cur.close(); conn.close()

    return redirect(url_for("usuarios"))

# ---------------------- CLIENTES ----------------------
@app.route("/clientes", methods=["GET", "POST"])
def clientes():
    rol_actual = session.get("rol")
    if rol_actual not in ["admin", "empleado"]:
        return render_template("error.html", mensaje="❌ Acceso denegado: no tienes permiso para ver clientes."), 403

    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        correo = request.form.get("correo", "").strip()
        telefono = request.form.get("telefono", "").strip()
        if not nombre or not correo:
            return render_template("error.html", mensaje="❌ Nombre y correo son obligatorios."), 400

        conn = obtener_conexion()
        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO clientes (nombre, correo, telefono) VALUES (%s, %s, %s)", (nombre, correo, telefono))
            conn.commit()
        except mysql.connector.Error as e:
            cur.close(); conn.close()
            return render_template("error.html", mensaje=f"❌ Error al guardar: {e}"), 500
        cur.close(); conn.close()
        return redirect(url_for("clientes"))

    conn = obtener_conexion()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id_cliente, nombre, correo, telefono FROM clientes ORDER BY nombre;")
    clientes = cur.fetchall()
    cur.close(); conn.close()

    return render_template(
        "clientes.html",
        clientes=clientes,
        user_name=session.get("user_name"),
        saludo=obtener_saludo(),
        rol=rol_actual
    )
    
    # ---- ELIMINAR CLIENTE ----
@app.route("/eliminar_cliente/<int:id_cliente>", methods=["POST"])
def eliminar_cliente(id_cliente):
    rol_actual = session.get("rol")
    if rol_actual not in ["admin", "empleado"]:
        return render_template("error.html", mensaje="❌ No tienes permiso para eliminar clientes."), 403

    conn = obtener_conexion()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM clientes WHERE id_cliente = %s", (id_cliente,))
        conn.commit()
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("clientes"))

# ---- EDITAR CLIENTE ----
@app.route("/editar_cliente/<int:id_cliente>", methods=["GET", "POST"])
def editar_cliente(id_cliente):
    rol_actual = session.get("rol")
    if rol_actual not in ["admin", "empleado"]:
        return render_template("error.html", mensaje="❌ No tienes permiso para editar clientes."), 403

    conn = obtener_conexion()
    cur = conn.cursor(dictionary=True)

    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        correo = request.form.get("correo", "").strip()
        telefono = request.form.get("telefono", "").strip()

        if not nombre or not correo:
            cur.close(); conn.close()
            return render_template("error.html", mensaje="❌ Nombre y correo son obligatorios."), 400

        cur.execute("""
            UPDATE clientes
            SET nombre=%s, correo=%s, telefono=%s
            WHERE id_cliente=%s
        """, (nombre, correo, telefono, id_cliente))
        conn.commit()
        cur.close(); conn.close()
        return redirect(url_for("clientes"))

    cur.execute("SELECT * FROM clientes WHERE id_cliente=%s", (id_cliente,))
    cliente = cur.fetchone()
    cur.close(); conn.close()

    if not cliente:
        return render_template("error.html", mensaje="❌ Cliente no encontrado."), 404

    return render_template(
        "editar_cliente.html",
        cliente=cliente,
        user_name=session.get("user_name"),
        saludo=obtener_saludo(),
        rol=rol_actual
    )

# ---- PROVEEDORES (listar + alta) ----
@app.route("/proveedores", methods=["GET", "POST"])
def proveedores():
    rol_actual = session.get("rol")
    if rol_actual not in ["admin", "empleado"]:
        return render_template("error.html", mensaje="❌ Acceso denegado: no tienes permiso para ver proveedores."), 403

    conn = obtener_conexion()
    cur = conn.cursor(dictionary=True)

    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        correo = request.form.get("correo", "").strip()
        telefono = request.form.get("telefono", "").strip()

        if not nombre or not correo:
            cur.close(); conn.close()
            return render_template("error.html", mensaje="❌ Nombre y correo son obligatorios."), 400

        cur.execute(
            "INSERT INTO proveedores (nombre, correo, telefono) VALUES (%s, %s, %s)",
            (nombre, correo, telefono)
        )
        conn.commit()

    cur.execute("SELECT id_proveedor, nombre, correo, telefono FROM proveedores ORDER BY nombre;")
    proveedores = cur.fetchall()
    cur.close(); conn.close()

    return render_template(
        "proveedores.html",
        proveedores=proveedores,
        user_name=session.get("user_name"),
        saludo=obtener_saludo(),
        rol=rol_actual
    )

# ---------------------- EDITAR PROVEEDOR ----------------------
@app.route("/editar_proveedor/<int:id_proveedor>", methods=["GET", "POST"])
def editar_proveedor(id_proveedor):
    rol_actual = session.get("rol")
    if rol_actual not in ["admin", "empleado"]:
        return render_template("error.html", mensaje="❌ No tienes permiso para editar proveedores."), 403

    conn = obtener_conexion()
    cur = conn.cursor(dictionary=True)

    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        correo = request.form.get("correo", "").strip()
        telefono = request.form.get("telefono", "").strip()
        direccion = request.form.get("direccion", "").strip()

        if not nombre or not correo or not telefono or not direccion:
            cur.close(); conn.close()
            return render_template("error.html", mensaje="❌ Completa todos los campos."), 400

        try:
            cur.execute("""
                UPDATE proveedores
                   SET nombre=%s, correo=%s, telefono=%s, direccion=%s
                 WHERE id_proveedor=%s
            """, (nombre, correo, telefono, direccion, id_proveedor))
            conn.commit()
        except mysql.connector.Error as e:
            cur.close(); conn.close()
            return render_template("error.html", mensaje=f"❌ Error al actualizar: {e}"), 500

        cur.close(); conn.close()
        flash("Proveedor actualizado correctamente ✅", "success")
        return redirect(url_for("proveedores"))

    cur.execute("SELECT * FROM proveedores WHERE id_proveedor = %s", (id_proveedor,))
    proveedor = cur.fetchone()
    cur.close(); conn.close()

    if not proveedor:
        return render_template("error.html", mensaje="❌ No se encontró el proveedor."), 404

    return render_template("editar_proveedor.html", proveedor=proveedor, rol=rol_actual)

# ---- ELIMINAR PROVEEDOR ----
@app.route("/eliminar_proveedor/<int:prov_id>", methods=["POST"])
def eliminar_proveedor(prov_id):
    rol_actual = session.get("rol")
    if rol_actual not in ["admin", "empleado"]:
        return render_template("error.html", mensaje="❌ Acceso denegado: no tienes permiso para eliminar proveedores."), 403

    conn = obtener_conexion()
    cur = conn.cursor()
    cur.execute("DELETE FROM proveedores WHERE id_proveedor = %s", (prov_id,))
    conn.commit()
    cur.close(); conn.close()

    return redirect(url_for("proveedores"))

# ---------------------- PEDIDOS DE CLIENTES ------
@app.route("/pedidos", methods=["GET", "POST"])
def pedidos():
    rol_actual = session.get("rol")
    if rol_actual not in ["admin", "empleado", "consultor"]:
        return render_template("error.html", mensaje="❌ Acceso denegado: no tienes permiso para ver pedidos."), 403

    conn = obtener_conexion()
    cur = conn.cursor(dictionary=True)
    try:
        if request.method == "POST":
            cliente = request.form.get("cliente", "").strip()
            codigo_pedido = request.form.get("codigo_pedido", "").strip()
            descripcion = request.form.get("descripcion", "").strip()
            medida = request.form.get("medida", "").strip()
            cantidad = request.form.get("cantidad", "").strip()
            estado_form = (request.form.get("estado") or "pendiente").strip().lower()

            if not cliente or not codigo_pedido or not descripcion or not medida or not cantidad:
                return render_template("error.html", mensaje="❌ Completa todos los campos del pedido."), 400

            try:
                cur.execute("""
                    INSERT INTO pedidos_clientes (cliente, codigo_pedido, descripcion, medida, cantidad, estado)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (cliente, codigo_pedido, descripcion, medida, int(cantidad), estado_form))
                conn.commit()
            except mysql.connector.Error as e:
                return render_template("error.html", mensaje=f"❌ Error al guardar: {e}"), 500

        cur.execute("SELECT id_cliente, nombre FROM clientes ORDER BY nombre;")
        clientes = cur.fetchall()

        filtro_estado = (request.args.get("estado") or "").strip().lower()
        estados_validos = {"pendiente","confirmado","enviado","entregado","cancelado"}

        if filtro_estado and filtro_estado in estados_validos:
            cur.execute("""
                SELECT id_pedidoc, cliente, codigo_pedido, descripcion, medida, cantidad, estado, fecha_estado
                FROM pedidos_clientes
                WHERE estado = %s
                ORDER BY id_pedidoc DESC;
            """, (filtro_estado,))
        else:
            cur.execute("""
                SELECT id_pedidoc, cliente, codigo_pedido, descripcion, medida, cantidad, estado, fecha_estado
                FROM pedidos_clientes
                ORDER BY id_pedidoc DESC;
            """)
        pedidos_cli = cur.fetchall()

        piezas = []
        if tabla_existe("catalogo"):
            cur.execute("SELECT ID_Item, SKU, Descripcion, Medida FROM catalogo ORDER BY SKU;")
            piezas = cur.fetchall()

        detalles = []
        if tabla_existe("pedido_detalle"):
            cur.execute("""
                SELECT d.id_detalle, d.id_pedido, p.codigo_pedido,
                       c.Descripcion AS nombre_pieza, d.cantidad AS cantidad_pieza, d.medida
                FROM pedido_detalle d
                JOIN pedidos_clientes p ON d.id_pedido = p.id_pedidoc
                LEFT JOIN catalogo c ON d.id_pieza = c.ID_Item
                ORDER BY d.id_detalle DESC;
            """)
            detalles = cur.fetchall()

    finally:
        cur.close(); conn.close()

    return render_template(
        "pedidos.html",
        clientes=clientes,
        pedidos=pedidos_cli,
        piezas=piezas,
        detalles=detalles,
        filtro_estado=filtro_estado,
        user_name=session.get("user_name"),
        saludo=obtener_saludo(),
        rol=rol_actual
    )

# ---------------------- PEDIDOS CONSULTOR (SOLO LECTURA) ----------------------
@app.route("/pedidos_consultor")
def pedidos_consultor():
    rol_actual = session.get("rol")
    if rol_actual != "consultor":
        return render_template("error.html", mensaje="❌ Acceso denegado: solo consultores pueden ver esto."), 403

    conn = obtener_conexion()
    cur = conn.cursor(dictionary=True)

    cur.execute("""
        SELECT id_pedidoc, cliente, codigo_pedido, descripcion, medida, cantidad, estado, fecha_estado
        FROM pedidos_clientes
        ORDER BY fecha_estado DESC;
    """)
    pedidos = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "pedidos_consultor.html",
        pedidos=pedidos,
        user_name=session.get("user_name"),
        saludo=obtener_saludo(),
        rol=rol_actual
    )

@app.route("/pedidos/<int:pedido_id>/estado", methods=["POST"])
def actualizar_estado_pedcli(pedido_id):
    """Actualiza el estado de un pedido de cliente."""
    rol_actual = session.get("rol")
    if rol_actual not in ["admin", "empleado"]:
        return render_template("error.html", mensaje="❌ No tienes permiso para cambiar estados."), 403

    nuevo_estado = (request.form.get("estado") or "").strip().lower()
    estados_validos = {"pendiente","confirmado","enviado","entregado","cancelado"}
    if nuevo_estado not in estados_validos:
        return render_template("error.html", mensaje="❌ Estado inválido."), 400

    conn = obtener_conexion()
    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE pedidos_clientes
               SET estado = %s
             WHERE id_pedidoc = %s
        """, (nuevo_estado, pedido_id))
        conn.commit()
    except mysql.connector.Error as e:
        cur.close(); conn.close()
        return render_template("error.html", mensaje=f"❌ Error al actualizar: {e}"), 500
    finally:
        cur.close(); conn.close()

    ref = request.args.get("ref")
    return redirect(ref if ref else url_for("pedidos"))


@app.route("/detalle_pedido", methods=["POST"])
def detalle_pedido():
    rol_actual = session.get("rol")
    if rol_actual not in ["admin", "empleado"]:
        return render_template("error.html", mensaje="❌ No tienes permiso para modificar pedidos."), 403

    if not tabla_existe("pedido_detalle"):
        return render_template("error.html", mensaje="❌ La tabla 'pedido_detalle' no existe en la BD. No se pueden guardar detalles."), 500

    id_pedido = request.form.get("id_pedido")
    id_pieza = request.form.get("id_pieza")
    cantidad = request.form.get("cantidad_pieza")
    medida = request.form.get("medida", "").strip()

    if not id_pedido or not id_pieza or not cantidad:
        return render_template("error.html", mensaje="❌ Completa todos los campos del detalle."), 400

    conn = obtener_conexion()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO pedido_detalle (id_pedido, id_pieza, cantidad, medida)
            VALUES (%s, %s, %s, %s)
        """, (int(id_pedido), int(id_pieza), int(cantidad), medida))
        conn.commit()
    except mysql.connector.Error as e:
        cur.close(); conn.close()
        return render_template("error.html", mensaje=f"❌ Error al guardar detalle: {e}"), 500
    finally:
        cur.close(); conn.close()

    return redirect(url_for("pedidos"))


@app.route("/eliminar_detalle/<int:id_detalle>", methods=["POST"])
def eliminar_detalle(id_detalle):
    rol_actual = session.get("rol")
    if rol_actual not in ["admin", "empleado"]:
        return render_template("error.html", mensaje="❌ No tienes permiso para eliminar detalle."), 403

    if not tabla_existe("pedido_detalle"):
        return render_template("error.html", mensaje="❌ La tabla 'pedido_detalle' no existe en la BD."), 500

    conn = obtener_conexion()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM pedido_detalle WHERE id_detalle=%s", (id_detalle,))
        conn.commit()
    finally:
        cur.close(); conn.close()

    return redirect(url_for("pedidos"))


# ---------------------- PEDIDOS PROVEEDORES ----------------------
@app.route("/pedidos_proveedores", methods=["GET", "POST"])
def pedidos_proveedores():
    rol_actual = session.get("rol")
    if rol_actual not in ["admin", "empleado"]:
        return render_template("error.html", mensaje="❌ No tienes permiso para ver pedidos de proveedores."), 403

    if request.method == "POST":
        proveedor = request.form.get("proveedor", "").strip()
        codigo_pedido = request.form.get("codigo_pedido", "").strip()
        descripcion = request.form.get("descripcion", "").strip()
        medida = request.form.get("medida", "").strip()
        cantidad = request.form.get("cantidad", "").strip()

        if not proveedor or not codigo_pedido or not descripcion or not medida or not cantidad:
            return render_template("error.html", mensaje="❌ Completa todos los campos del pedido."), 400

        conn = obtener_conexion()
        cur = conn.cursor()
        try:
            cur.execute("""
                INSERT INTO pedidos_proveedores (proveedor, codigo_pedido, descripcion, medida, cantidad, estado)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (proveedor, codigo_pedido, descripcion, medida, int(cantidad), 'pendiente'))
            conn.commit()
        except mysql.connector.Error as e:
            cur.close(); conn.close()
            return render_template("error.html", mensaje=f"❌ Error al guardar: {e}"), 500
        cur.close(); conn.close()
        return redirect(url_for("pedidos_proveedores"))

    filtro_estado = request.args.get("estado", "").strip()
    estados_validos = {"pendiente","confirmado","enviado","recibido","cancelado"}

    conn = obtener_conexion()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute("SELECT id_proveedor, nombre FROM proveedores ORDER BY nombre;")
        proveedores = cur.fetchall()

        if filtro_estado and filtro_estado in estados_validos:
            cur.execute("""
                SELECT id_pedidop, proveedor, codigo_pedido, descripcion, medida, cantidad, estado, fecha_estado
                FROM pedidos_proveedores
                WHERE estado = %s
                ORDER BY id_pedidop DESC;
            """, (filtro_estado,))
        else:
            cur.execute("""
                SELECT id_pedidop, proveedor, codigo_pedido, descripcion, medida, cantidad, estado, fecha_estado
                FROM pedidos_proveedores
                ORDER BY id_pedidop DESC;
            """)
        pedidos_prov = cur.fetchall()
    finally:
        cur.close(); conn.close()

    return render_template(
        "pedidos_proveedores.html",
        proveedores=proveedores,
        pedidos=pedidos_prov,
        filtro_estado=filtro_estado,
        user_name=session.get("user_name"),
        saludo=obtener_saludo(),
        rol=rol_actual
    )

@app.route("/pedidos_proveedores/<int:pedido_id>/estado", methods=["POST"])
def actualizar_estado_pedprov(pedido_id):
    rol_actual = session.get("rol")
    if rol_actual not in ["admin", "empleado"]:
        return render_template("error.html", mensaje="❌ No tienes permiso para cambiar estados."), 403

    nuevo_estado = request.form.get("estado", "").strip()
    estados_validos = {"pendiente","confirmado","enviado","recibido","cancelado"}
    if nuevo_estado not in estados_validos:
        return render_template("error.html", mensaje="❌ Estado inválido."), 400

    conn = obtener_conexion()
    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE pedidos_proveedores
            SET estado = %s
            WHERE id_pedidop = %s
        """, (nuevo_estado, pedido_id))
        conn.commit()
    except mysql.connector.Error as e:
        cur.close(); conn.close()
        return render_template("error.html", mensaje=f"❌ Error al actualizar: {e}"), 500
    cur.close(); conn.close()

    ref = request.args.get("ref")
    return redirect(ref if ref else url_for("pedidos_proveedores"))

# ---------------------- CATALOGO ----------------------
@app.route("/catalogo")
def catalogo():
    rol_actual = session.get("rol")
    conn = obtener_conexion()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT SKU, Tipo_de_pieza, Descripcion, Medida, Unidades, Precio
        FROM catalogo
        ORDER BY Tipo_de_pieza, SKU;
    """)
    items = cur.fetchall()
    cur.close(); conn.close()

    return render_template(
        "catalogo.html",
        items=items,
        user_name=session.get("user_name"),
        saludo=obtener_saludo(),
        rol=rol_actual
    )

@app.route("/agregar_pieza")
def agregar_pieza():
    return redirect(url_for("catalogo"))

@app.route("/guardar_pieza", methods=["POST"])
def guardar_pieza():
    sku_original = request.form.get("sku_original", "").strip()
    SKU = request.form.get("SKU", "").strip()
    Tipo = request.form.get("Tipo_de_pieza", "").strip()
    Descripcion = request.form.get("Descripcion", "").strip()
    Medida = request.form.get("Medida", "").strip()
    Unidades = request.form.get("Unidades", "").strip()
    Precio = request.form.get("Precio", "").strip()

    if not SKU or not Tipo or not Unidades or not Precio:
        return render_template("error.html", mensaje="❌ Campos obligatorios faltantes para la pieza."), 400

    conn = obtener_conexion()
    cur = conn.cursor()
    try:
        if sku_original:
            cur.execute("""
                UPDATE catalogo
                SET SKU=%s, Tipo_de_pieza=%s, Descripcion=%s, Medida=%s, Unidades=%s, Precio=%s
                WHERE SKU=%s
            """, (SKU, Tipo, Descripcion, Medida, int(Unidades), float(Precio), sku_original))
        else:
            cur.execute("""
                INSERT INTO catalogo (SKU, Tipo_de_pieza, Descripcion, Medida, Unidades, Precio)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (SKU, Tipo, Descripcion, Medida, int(Unidades), float(Precio)))
        conn.commit()
    except mysql.connector.Error as e:
        cur.close(); conn.close()
        return render_template("error.html", mensaje=f"❌ Error al guardar la pieza: {e}"), 500
    finally:
        cur.close(); conn.close()

    return redirect(url_for("catalogo"))

@app.route("/eliminar_pieza/<sku>", methods=["POST"])
def eliminar_pieza_por_sku(sku):
    rol_actual = session.get("rol")
    if rol_actual not in ["admin", "empleado"]:
        return render_template("error.html", mensaje="❌ No tienes permiso para eliminar piezas."), 403

    conn = obtener_conexion()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM catalogo WHERE SKU=%s", (sku,))
        conn.commit()
    finally:
        cur.close(); conn.close()
    return redirect(url_for("catalogo"))

@app.route("/eliminar_pieza_id/<int:id>", methods=["POST"])
def eliminar_pieza(id):
    rol_actual = session.get("rol")
    if rol_actual not in ["admin", "empleado"]:
        return render_template("error.html", mensaje="❌ No tienes permiso para eliminar piezas."), 403

    conn = obtener_conexion()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM catalogo WHERE ID_Item=%s", (id,))
        conn.commit()
    finally:
        cur.close(); conn.close()
    return redirect(url_for("catalogo"))

@app.route("/editar_pieza/<int:id>", methods=["GET", "POST"])
def editar_pieza(id):
    rol_actual = session.get("rol")
    if rol_actual not in ["admin", "empleado"]:
        return render_template("error.html", mensaje="❌ No tienes permiso para editar piezas."), 403

    conn = obtener_conexion()
    cur = conn.cursor(dictionary=True)
    try:
        if request.method == "POST":
            tipo = request.form.get("tipo", "").strip()
            descripcion = request.form.get("descripcion", "").strip()
            medida = request.form.get("medida", "").strip()
            precio = request.form.get("precio", "").strip()

            if not tipo or not descripcion or not precio:
                return render_template("error.html", mensaje="❌ Campos obligatorios faltantes."), 400

            cur.execute("""
                UPDATE catalogo SET Tipo_de_pieza=%s, Descripcion=%s, Medida=%s, Precio=%s WHERE ID_Item=%s
            """, (tipo, descripcion, medida, float(precio), id))
            conn.commit()
            return redirect(url_for("catalogo"))

        cur.execute("SELECT * FROM catalogo WHERE ID_Item=%s", (id,))
        pieza = cur.fetchone()
    finally:
        cur.close(); conn.close()

    if not pieza:
        return render_template("error.html", mensaje="❌ Pieza no encontrada."), 404

    return render_template("editar_pieza.html", pieza=pieza,
                           user_name=session.get("user_name"), saludo=obtener_saludo(), rol=rol_actual)

# ---------------------- INVENTARIO ----------------------
@app.route("/inventario")
def inventario():
    rol_actual = session.get("rol")
    if rol_actual not in ["admin", "empleado", "consultor"]:
        return render_template("error.html", mensaje="❌ Acceso denegado: no tienes permiso para ver inventario."), 403

    conn = obtener_conexion()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute("""
            SELECT 
                i.ID_Item,
                c.SKU,
                c.Tipo_de_pieza,
                c.Descripcion,
                c.Medida,
                c.Precio,
                i.stock,
                i.stock_min
            FROM inventario i
            JOIN catalogo c ON i.ID_Item = c.ID_Item
            ORDER BY c.Tipo_de_pieza, c.SKU;
        """)
        inventario = cur.fetchall()
    finally:
        cur.close(); conn.close()

    return render_template(
        "inventario.html",
        inventario=inventario,
        user_name=session.get("user_name"),
        saludo=obtener_saludo(),
        rol=rol_actual
    )

@app.route("/actualizar_stock", methods=["POST"])
def actualizar_stock():
    rol_actual = session.get("rol")
    if rol_actual not in ["admin", "empleado"]:
        return render_template("error.html", mensaje="❌ No tienes permiso para actualizar el inventario."), 403

    id_item = request.form.get("id_item")
    nuevo_stock = request.form.get("nuevo_stock")

    if not id_item or not nuevo_stock:
        return render_template("error.html", mensaje="❌ Faltan datos para actualizar stock."), 400

    conn = obtener_conexion()
    cur = conn.cursor()
    try:
        cur.execute("UPDATE inventario SET stock = %s WHERE ID_Item = %s", (int(nuevo_stock), int(id_item)))
        conn.commit()
    finally:
        cur.close(); conn.close()

    return redirect(url_for("inventario"))

# ---------------------- CHECAR CONEXIÓN ----------------------
@app.route("/dbcheck")
def dbcheck():
    try:
        conn = obtener_conexion()
        cur = conn.cursor()
        cur.execute("SELECT DATABASE(), @@port")
        db, port = cur.fetchone()
        cur.close(); conn.close()
        return f"DB OK → database={db}, port={port}"
    except Exception as e:
        return f"DB ERROR: {e}", 500

# ---------------------- CAMBIAR CONTRASEÑA ----------------------
@app.route("/cambiar_contrasena", methods=["GET", "POST"])
def cambiar_contrasena():
    if "user_name" not in session:
        return redirect(url_for("index"))

    if request.method == "POST":
        actual = request.form.get("actual", "").strip()
        nueva = request.form.get("nueva", "").strip()
        confirmar = request.form.get("confirmar", "").strip()

        if not actual or not nueva or not confirmar:
            return render_template("error.html", mensaje="❌ Debes llenar todos los campos."), 400
        if nueva != confirmar:
            return render_template("error.html", mensaje="❌ Las contraseñas nuevas no coinciden."), 400
        if not validar_contrasena(nueva):
            return render_template("error.html", mensaje="❌ La nueva contraseña no cumple con los requisitos."), 400

        correo = session.get("correo")
        conn = obtener_conexion()
        cur = conn.cursor(dictionary=True)
        try:
            cur.execute("SELECT id, contrasena FROM usuarios WHERE correo = %s", (correo,))
            user = cur.fetchone()

            if not user or not bcrypt.checkpw(actual.encode("utf-8"), user["contrasena"].encode("utf-8")):
                return render_template("error.html", mensaje="❌ Contraseña actual incorrecta."), 401

            nueva_hash = bcrypt.hashpw(nueva.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            cur.execute("UPDATE usuarios SET contrasena = %s WHERE id = %s", (nueva_hash, user["id"]))
            conn.commit()
        finally:
            cur.close(); conn.close()

        return render_template("mensaje.html", mensaje="✅ Contraseña actualizada correctamente.",
                               user_name=session.get("user_name"),
                               saludo=obtener_saludo(),
                               rol=session.get("rol"))

    return render_template("cambiar_contrasena.html",
                           user_name=session.get("user_name"),
                           saludo=obtener_saludo(),
                           rol=session.get("rol"))
    # ---------------------- REPORTES ADMIN (MOVIMIENTOS + PEDIDOS) ----------------------
@app.route("/reportes_admin")
def reportes_admin():
    rol_actual = session.get("rol")
    if rol_actual != "admin":
        return render_template("error.html", mensaje="❌ Solo un administrador puede acceder a reportes avanzados."), 403

    conn = obtener_conexion()
    cur = conn.cursor(dictionary=True)

    # Pedidos de clientes
    cur.execute("SELECT * FROM pedidos_clientes ORDER BY fecha_estado DESC")
    pedidos_clientes = cur.fetchall()

    # Pedidos a proveedores
    cur.execute("SELECT * FROM pedidos_proveedores ORDER BY fecha_estado DESC")
    pedidos_proveedores = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "reportes_admin.html",
        pedidos_clientes=pedidos_clientes,
        pedidos_proveedores=pedidos_proveedores,
        user_name=session.get("user_name"),
        saludo=obtener_saludo(),
        rol=rol_actual
    )
@app.route("/reportes_consultor")
def reportes_consultor():
    rol_actual = session.get("rol")
    if rol_actual != "consultor":
        return render_template("error.html", mensaje="Acceso solo para consultores."), 403

    return render_template(
        "reportes_consultor.html",
        user_name=session.get("user_name"),
        saludo=obtener_saludo(),
        rol=rol_actual
    )



# ---------------------- REPORTES ----------------------
@app.route("/reportes")
def reportes():
    rol_actual = session.get("rol")
    if rol_actual not in ["admin", "consultor"]:
        return render_template("error.html", mensaje="❌ Acceso denegado: no tienes permiso para ver reportes."), 403

    return render_template(
        "reportes.html",
        user_name=session.get("user_name"),
        saludo=obtener_saludo(),
        rol=rol_actual
    )

# REPORTE: PEDIDOS DE CLIENTES
@app.route("/reporte_pedidos_clientes")
def reporte_pedidos_clientes():
    rol_actual = session.get("rol")
    if rol_actual not in ["admin", "consultor"]:
        return render_template("error.html", mensaje="❌ No tienes permiso para generar este reporte."), 403

    conn = obtener_conexion()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute("SELECT cliente, codigo_pedido, descripcion, medida, cantidad FROM pedidos_clientes ORDER BY id_pedidoc DESC")
        pedidos = cur.fetchall()
    finally:
        cur.close(); conn.close()

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    pdf.setTitle("Reporte de Pedidos de Clientes")

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(180, 750, "REPORTE DE PEDIDOS DE CLIENTES")
    pdf.setFont("Helvetica", 12)
    pdf.drawString(50, 730, f"Generado por: {session.get('user_name')}")
    pdf.drawString(400, 730, f"Fecha: {datetime.now().strftime('%d/%m/%Y')}")

    y = 700
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(50, y, "Cliente")
    pdf.drawString(160, y, "Código")
    pdf.drawString(250, y, "Descripción")
    pdf.drawString(400, y, "Medida")
    pdf.drawString(480, y, "Cant.")
    pdf.line(45, y-5, 560, y-5)

    pdf.setFont("Helvetica", 11)
    y -= 20
    for pedido in pedidos:
        pdf.drawString(50, y, str(pedido["cliente"])[:20])
        pdf.drawString(160, y, str(pedido["codigo_pedido"]))
        pdf.drawString(250, y, str(pedido["descripcion"])[:25])
        pdf.drawString(400, y, str(pedido["medida"]))
        pdf.drawString(480, y, str(pedido["cantidad"]))
        y -= 18
        if y < 80:
            pdf.showPage()
            y = 750

    pdf.save()
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="reporte_pedidos_clientes.pdf", mimetype="application/pdf")

# REPORTE: INVENTARIO
@app.route("/reporte_inventario")
def reporte_inventario():
    rol_actual = session.get("rol")
    if rol_actual not in ["admin", "consultor"]:
        return render_template("error.html", mensaje="❌ No tienes permiso para generar este reporte."), 403

    conn = obtener_conexion()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute("""
            SELECT 
                c.SKU,
                c.Tipo_de_pieza,
                c.Descripcion,
                c.Medida,
                c.Precio,
                i.stock,
                i.stock_min
            FROM inventario i
            JOIN catalogo c ON i.ID_Item = c.ID_Item
            ORDER BY c.Tipo_de_pieza, c.SKU
        """)
        inventario = cur.fetchall()
    finally:
        cur.close(); conn.close()

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(letter), rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    styles = getSampleStyleSheet()
    elementos = []
    titulo = Paragraph("📦 Reporte de Inventario - Industrial Parts", styles["Title"])
    elementos.append(titulo)
    elementos.append(Spacer(1, 12))

    encabezados = ["SKU", "Tipo de pieza", "Descripción", "Medida", "Stock", "Stock mín.", "Precio (MXN)"]
    datos_tabla = [encabezados]
    for item in inventario:
        fila = [
            item["SKU"],
            item["Tipo_de_pieza"],
            item["Descripcion"],
            item["Medida"],
            str(item["stock"]),
            str(item["stock_min"]),
            f"{item['Precio']:.2f}"
        ]
        datos_tabla.append(fila)

    tabla = Table(datos_tabla, colWidths=[3.5*cm, 4.5*cm, 6.5*cm, 3.5*cm, 2.5*cm, 2.8*cm, 3*cm])
    tabla.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0074D9")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
    ]))
    elementos.append(tabla)
    doc.build(elementos)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="reporte_inventario.pdf", mimetype="application/pdf")

# REPORTE: CATALOGO
@app.route("/reporte_catalogo")
def reporte_catalogo():
    rol_actual = session.get("rol")
    if rol_actual not in ["admin", "consultor"]:
        return render_template("error.html", mensaje="❌ No tienes permiso para generar este reporte."), 403

    conn = obtener_conexion()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute("SELECT SKU, Tipo_de_pieza, Descripcion, Medida, Unidades, Precio FROM catalogo ORDER BY Tipo_de_pieza, SKU")
        catalogo = cur.fetchall()
    finally:
        cur.close(); conn.close()

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(letter), rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    styles = getSampleStyleSheet()
    elementos = []
    titulo = Paragraph("📘 Reporte del Catálogo de Piezas Industriales", styles["Title"])
    elementos.append(titulo)
    elementos.append(Spacer(1, 12))

    encabezados = ["SKU", "Tipo de pieza", "Descripción", "Medida", "Unidades", "Precio ($)"]
    datos_tabla = [encabezados]
    for item in catalogo:
        fila = [
            item["SKU"],
            item["Tipo_de_pieza"],
            item["Descripcion"],
            item["Medida"],
            str(item["Unidades"]),
            f"{item['Precio']:.2f}"
        ]
        datos_tabla.append(fila)

    tabla = Table(datos_tabla, colWidths=[3.5*cm, 4.5*cm, 6.5*cm, 3.5*cm, 3*cm, 3*cm])
    tabla.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0074D9")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
    ]))
    elementos.append(tabla)
    doc.build(elementos)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="reporte_catalogo.pdf", mimetype="application/pdf")

# ---------------------- EJECUCIÓN ----------------------
if __name__ == "__main__":
    from waitress import serve
    serve(app, host="0.0.0.0", port=8080)
