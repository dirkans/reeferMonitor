from passlib.context import CryptContext
import mysql.connector

# Configuración (Usa tus credenciales reales)
db_config = {
    'user': 'iot_user',
    'password': '062292',
    'host': '127.0.0.1',
    'database': 'reefer_iot'
}

# 1. Generar el hash compatible con TU sistema
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
nuevo_password = "admin123"
hash_calculado = pwd_context.hash(nuevo_password)

print(f"Generando hash nuevo...")

# 2. Actualizar la base de datos
try:
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    
    # Actualizamos el usuario admin
    sql = "UPDATE users SET password_hash = %s WHERE username = 'admin'"
    cursor.execute(sql, (hash_calculado,))
    conn.commit()
    
    if cursor.rowcount > 0:
        print("✅ ¡ÉXITO! Contraseña restablecida a: admin123")
    else:
        print("⚠️ OJO: No se encontró el usuario 'admin' en la tabla. ¿Quizás no se creó?")
        # Intento de crearlo si no existe
        print("Intentando crear el usuario de cero...")
        cursor.execute("INSERT INTO users (username, password_hash, is_admin) VALUES ('admin', %s, TRUE)", (hash_calculado,))
        conn.commit()
        print("✅ Usuario 'admin' creado y contraseña establecida.")

    cursor.close()
    conn.close()

except Exception as e:
    print(f"❌ Error conectando a la DB: {e}")
