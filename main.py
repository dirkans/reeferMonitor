from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional
import mysql.connector
from jose import JWTError, jwt
from passlib.context import CryptContext
from pywebpush import webpush, WebPushException
import json
import asyncio
from datetime import datetime, timedelta

# PEGA TUS LLAVES DE VAPIDKEYS.COM AQUI:
VAPID_PUBLIC_KEY = "BFcBoXl5oQ6kCA345y5SzPgCgSrEAnaCDWwim65ajHYh126uj6HwNCxPAIta0urS4rC_i2gODtF1SXVbtOvlcmg"
VAPID_PRIVATE_KEY = "t4YJklmeFN8ZilDCJxgYR_jOyzWEOV803BrtVBkKVW8"
VAPID_CLAIMS = {"sub": "mailto:dirkans@hotmail.com"}

class PushSubscription(BaseModel):
    endpoint: str
    keys: dict

# --- CONFIGURACION ---
SECRET_KEY = "tu_secreto_super_seguro_cambialo"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

db_config = {'user': 'iot_user', 'password': '062292', 'host': '127.0.0.1', 'database': 'reefer_iot'}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

class Token(BaseModel): access_token: str; token_type: str
class UserCreate(BaseModel): username: str; password: str; role: str = "cliente"
class UserReset(BaseModel): user_id: int; new_password: str
class UserDelete(BaseModel): user_id: int
class DeviceAssign(BaseModel): username: str; device_id: str
class DeviceDelete(BaseModel): device_id: str
class AssignmentAction(BaseModel): assignment_id: int
class RelayCommand(BaseModel): device_id: str; relay_name: str; state: bool
class WifiCommand(BaseModel): device_id: str
class DeviceSettings(BaseModel):
    device_id: str
    setpoint: float
    tolerancia_temp: float
    tiempo_caliente: int
    tiempo_apagado: int
    tiempo_offline: int
class LecturaCompleta(BaseModel):
    device_id: str; temp_return: float; temp_supply: float; temp_evap: float; amp_r: float; amp_s: float; amp_t: float; rssi: int; real_comp: int; real_evap: int; real_cond: int; real_heat: int; real_reefer: int

def get_db(): return mysql.connector.connect(**db_config)
def verify_pass(p, h): return pwd_context.verify(p, h)
def get_hash(p): return pwd_context.hash(p)
def create_token(data: dict):
    to_encode = data.copy()
    to_encode.update({"exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# --- AHORA EXTRAEMOS EL ROL DEL TOKEN ---
async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role", "cliente")
        if username is None: raise HTTPException(status_code=401)
    except JWTError: raise HTTPException(status_code=401)
    return {"username": username, "role": role}
@app.get("/", response_class=HTMLResponse)
async def ver_index(): return FileResponse("index.html")
@app.get("/login", response_class=HTMLResponse)
async def ver_login(): return FileResponse("login.html")
@app.get("/panel", response_class=HTMLResponse)
async def ver_panel(): return FileResponse("panel.html")
@app.get("/sw.js")
async def serve_sw(): return FileResponse("sw.js", media_type="application/javascript")
@app.get("/manifest.json")
async def serve_manifest(): return FileResponse("manifest.json", media_type="application/json")
@app.get("/logo.jpg")
async def serve_logo(): return FileResponse("logo.jpg", media_type="image/jpeg")
@app.get("/icon.png")
async def serve_icon(): return FileResponse("icon.png", media_type="image/png")
@app.get("/dashboard.png")
async def serve_dashboard(): return FileResponse("dashboard.png", media_type="image/png")

registro_alarmas = {}

async def motor_de_alarmas():
    print("🤖 Motor de Alarmas Inteligente: INICIADO")
    while True:
        try:
            conn = get_db()
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("SELECT device_id, setpoint, tolerancia_temp, tiempo_caliente FROM device_config")
            equipos = cursor.fetchall()
            
            for eq in equipos:
                dev_id = eq['device_id']
                setpoint = eq['setpoint']
                tolerancia = eq['tolerancia_temp']
                t_caliente = eq['tiempo_caliente']
                
                cursor.execute("SELECT val_return, created_at FROM device_data WHERE device_id = %s ORDER BY created_at DESC LIMIT 1", (dev_id,))
                last_data = cursor.fetchone()
                
                if not last_data:
                    continue 
                    
                limite_maximo = setpoint + tolerancia
                
                if last_data['val_return'] > limite_maximo:
                    
                    query_historico = """
                        SELECT COUNT(*) as buenas 
                        FROM device_data 
                        WHERE device_id = %s 
                        AND val_return <= %s 
                        AND created_at >= NOW() - INTERVAL %s MINUTE
                    """
                    cursor.execute(query_historico, (dev_id, limite_maximo, t_caliente))
                    resultado = cursor.fetchone()
                    
                    if resultado['buenas'] == 0:
                        
                        ultima_vez = registro_alarmas.get(dev_id)
                        if not ultima_vez or (datetime.now() - ultima_vez) > timedelta(hours=2):
                            
                            print(f"⚠️ DISPARANDO ALARMA PUSH PARA: {dev_id}")
                            
                            cursor.execute("""
                                SELECT users.username 
                                FROM users 
                                JOIN user_devices ON users.id = user_devices.user_id 
                                WHERE user_devices.device_id = %s
                            """, (dev_id,))
                            dueños = cursor.fetchall()
                            
                            for dueño in dueños:
                                username = dueño['username']
                                cursor.execute("SELECT * FROM push_subscriptions WHERE username = %s", (username,))
                                subs = cursor.fetchall()
                                
                                payload = {
                                    "title": f"⚠️ ALERTA: Equipo {dev_id}",
                                    "body": f"El Return ({last_data['val_return']}°C) superó el límite por más de {t_caliente} minutos."
                                }
                                
                                for s in subs:
                                    try:
                                        webpush(
                                            subscription_info={"endpoint": s['endpoint'], "keys": {"p256dh": s['p256dh'], "auth": s['auth']}},
                                            data=json.dumps(payload),
                                            vapid_private_key=VAPID_PRIVATE_KEY,
                                            vapid_claims=VAPID_CLAIMS
                                        )
                                    except Exception as e:
                                        print(f"Error enviando push a {username}:", e)
                            
                            registro_alarmas[dev_id] = datetime.now()
                            
                else:
                    if dev_id in registro_alarmas:
                        print(f"✅ EQUIPO {dev_id} RECUPERADO. Alarma reseteada.")
                        del registro_alarmas[dev_id]
            
            conn.close()
        except Exception as e:
            print("Error en el Motor de Alarmas:", e)
            
        await asyncio.sleep(60)

@app.on_event("startup")
async def iniciar_tareas_de_fondo():
    asyncio.create_task(motor_de_alarmas())

@app.post("/token", response_model=Token)
async def login(form: OAuth2PasswordRequestForm = Depends()):
    conn = get_db(); cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username = %s", (form.username,))
    user = cursor.fetchone(); conn.close()
    if not user or not verify_pass(form.password, user['password_hash']): raise HTTPException(status_code=401)
    # Incluimos el ROL en el token
    return {"access_token": create_token({"sub": user['username'], "role": user['role']}), "token_type": "bearer"}

@app.post("/api/datos")
async def recibir_datos_iot(d: LecturaCompleta):
    conn = get_db(); cursor = conn.cursor(dictionary=True)
    try:
        sql = "INSERT INTO lecturas (device_id, temperatura, temp_supply, temp_evap, amp_r, amp_s, amp_t, rssi, real_comp, real_evap, real_cond, real_heat, real_reefer) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
        cursor.execute(sql, (d.device_id, d.temp_return, d.temp_supply, d.temp_evap, d.amp_r, d.amp_s, d.amp_t, d.rssi, d.real_comp, d.real_evap, d.real_cond, d.real_heat, d.real_reefer))
        cursor.execute("SELECT * FROM device_config WHERE device_id = %s", (d.device_id,))
        config = cursor.fetchone()
        if not config:
            cursor.execute("INSERT INTO device_config (device_id) VALUES (%s)", (d.device_id,))
            config = {'relay_compresor':0, 'relay_evaporador':0, 'relay_condensador':0, 'relay_resistencia':0, 'relay_reefer':0, 'reset_wifi':0}
        if config.get('reset_wifi') == 1: cursor.execute("UPDATE device_config SET reset_wifi = 0 WHERE device_id = %s", (d.device_id,))
        conn.commit()
    except Exception as e: print(e); return {"status": "error"}
    finally: conn.close()
    
    return {"status": "ok", "reset_wifi": int(config.get('reset_wifi', 0)), "relays": {"comp": int(config['relay_compresor']), "evap": int(config['relay_evaporador']), "cond": int(config['relay_condensador']), "heat": int(config['relay_resistencia']), "reefer": int(config['relay_reefer'])}}

# --- ENDPOINTS PROTEGIDOS POR ROLES ---

@app.post("/admin/reset_wifi")
async def reset_wifi_device(cmd: WifiCommand, current_user: dict = Depends(get_current_user)):
    if current_user['role'] != 'super_admin': raise HTTPException(status_code=403, detail="Solo Super Admin")
    conn = get_db(); cursor = conn.cursor(); cursor.execute("UPDATE device_config SET reset_wifi = 1 WHERE device_id = %s", (cmd.device_id,)); conn.commit(); conn.close()
    return {"msg": "Orden de reinicio WiFi enviada."}

@app.post("/admin/delete_device")
async def delete_device(cmd: DeviceDelete, current_user: dict = Depends(get_current_user)):
    if current_user['role'] != 'super_admin': raise HTTPException(status_code=403, detail="Solo Super Admin")
    conn = get_db(); cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM user_devices WHERE device_id = %s", (cmd.device_id,))
        cursor.execute("DELETE FROM lecturas WHERE device_id = %s", (cmd.device_id,))
        cursor.execute("DELETE FROM device_config WHERE device_id = %s", (cmd.device_id,))
        conn.commit()
    except Exception as e: conn.close(); raise HTTPException(status_code=400, detail=str(e))
    conn.close(); return {"msg": "Equipo eliminado correctamente"}

@app.post("/admin/control_relay")
async def control_relay(cmd: RelayCommand, current_user: dict = Depends(get_current_user)):
    if current_user['role'] not in ['super_admin', 'admin']: raise HTTPException(status_code=403, detail="Permiso Denegado")
    conn = get_db(); cursor = conn.cursor(dictionary=True)
    cursor.execute(f"UPDATE device_config SET relay_{cmd.relay_name} = %s WHERE device_id = %s", (cmd.state, cmd.device_id)); conn.commit(); conn.close()
    return {"msg": "Comando enviado"}

@app.get("/api/estado_actual/{device_id}")
async def get_estado(device_id: str, current_user: dict = Depends(get_current_user)):
    conn = get_db(); cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM lecturas WHERE device_id = %s ORDER BY fecha DESC LIMIT 1", (device_id,))
    lectura = cursor.fetchone()
    cursor.execute("SELECT * FROM device_config WHERE device_id = %s", (device_id,))
    config = cursor.fetchone(); conn.close()
    return {"lectura": lectura, "config": config}

@app.get("/api/historial/{device_id}")
async def historial(device_id: str, inicio: Optional[str] = None, fin: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    conn = get_db(); cursor = conn.cursor(dictionary=True)
    if not inicio or not fin: cursor.execute("SELECT * FROM lecturas WHERE device_id = %s ORDER BY fecha DESC LIMIT 2000", (device_id,))
    else: cursor.execute("SELECT * FROM lecturas WHERE device_id = %s AND fecha BETWEEN %s AND %s ORDER BY fecha ASC", (device_id, inicio, fin))
    res = cursor.fetchall(); conn.close()
    if not inicio: return res[::-1] 
    return res

@app.get("/my/devices")
async def get_my_devices(current_user: dict = Depends(get_current_user)):
    conn = get_db(); cursor = conn.cursor(dictionary=True)
    if current_user['role'] in ['super_admin', 'admin']: 
        cursor.execute("SELECT device_id, TIMESTAMPDIFF(SECOND, MAX(fecha), NOW()) as segundos_atras FROM lecturas GROUP BY device_id")
    else: 
        cursor.execute("SELECT d.device_id, TIMESTAMPDIFF(SECOND, MAX(l.fecha), NOW()) as segundos_atras FROM user_devices d JOIN users u ON d.user_id = u.id LEFT JOIN lecturas l ON d.device_id = l.device_id WHERE u.username = %s AND d.is_active = 1 GROUP BY d.device_id", (current_user['username'],))
    devices = cursor.fetchall(); conn.close(); return devices

@app.get("/admin/users_list")
async def get_users_list(current_user: dict = Depends(get_current_user)): 
    if current_user['role'] not in ['super_admin', 'admin']: raise HTTPException(status_code=403)
    conn = get_db(); cursor = conn.cursor(dictionary=True); cursor.execute("SELECT id, username, role, created_at FROM users"); users = cursor.fetchall(); conn.close(); return users

@app.post("/admin/reset_password")
async def reset_password(reset_data: UserReset, current_user: dict = Depends(get_current_user)): 
    if current_user['role'] not in ['super_admin', 'admin']: raise HTTPException(status_code=403)
    conn = get_db(); cursor = conn.cursor(); cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (get_hash(reset_data.new_password), reset_data.user_id)); conn.commit(); conn.close(); return {"msg": "Clave actualizada"}

@app.post("/admin/delete_user")
async def delete_user(delete_data: UserDelete, current_user: dict = Depends(get_current_user)): 
    if current_user['role'] != 'super_admin': raise HTTPException(status_code=403, detail="Solo Super Admin")
    conn = get_db(); cursor = conn.cursor(); cursor.execute("DELETE FROM users WHERE id = %s", (delete_data.user_id,)); conn.commit(); conn.close(); return {"msg": "Usuario eliminado"}

@app.get("/admin/assignments")
async def get_assignments(current_user: dict = Depends(get_current_user)): 
    if current_user['role'] not in ['super_admin', 'admin']: raise HTTPException(status_code=403)
    conn = get_db(); cursor = conn.cursor(dictionary=True); cursor.execute("SELECT ud.id, u.username, ud.device_id, ud.is_active FROM user_devices ud JOIN users u ON ud.user_id = u.id"); data = cursor.fetchall(); conn.close(); return data

@app.post("/admin/toggle_active")
async def toggle_active(action: AssignmentAction, current_user: dict = Depends(get_current_user)): 
    if current_user['role'] not in ['super_admin', 'admin']: raise HTTPException(status_code=403)
    conn = get_db(); cursor = conn.cursor(); cursor.execute("UPDATE user_devices SET is_active = NOT is_active WHERE id = %s", (action.assignment_id,)); conn.commit(); conn.close(); return {"msg": "Estado actualizado"}

@app.post("/admin/delete_assignment")
async def delete_assignment(action: AssignmentAction, current_user: dict = Depends(get_current_user)): 
    if current_user['role'] not in ['super_admin', 'admin']: raise HTTPException(status_code=403)
    conn = get_db(); cursor = conn.cursor(); cursor.execute("DELETE FROM user_devices WHERE id = %s", (action.assignment_id,)); conn.commit(); conn.close(); return {"msg": "Asignacion eliminada"}

@app.post("/admin/users")
async def create_user(new_user: UserCreate, current_user: dict = Depends(get_current_user)): 
    if current_user['role'] not in ['super_admin', 'admin']: raise HTTPException(status_code=403)
    conn = get_db(); cursor = conn.cursor()
    # Por seguridad, si Ivan crea un usuario, forzamos a que sea 'cliente'
    if current_user['role'] == 'admin' and new_user.role == 'super_admin': raise HTTPException(status_code=403, detail="No podes crear Super Admins")
    cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)", (new_user.username, get_hash(new_user.password), new_user.role)); conn.commit(); conn.close(); return {"msg": "Usuario creado"}

@app.post("/admin/assign")
async def assign_device(assignment: DeviceAssign, current_user: dict = Depends(get_current_user)): 
    if current_user['role'] not in ['super_admin', 'admin']: raise HTTPException(status_code=403)
    conn = get_db(); cursor = conn.cursor(); cursor.execute("SELECT id FROM users WHERE username = %s", (assignment.username,)); row = cursor.fetchone(); cursor.execute("INSERT INTO user_devices (user_id, device_id) VALUES (%s, %s)", (row[0], assignment.device_id)); conn.commit(); conn.close(); return {"msg": "Asignado"}

@app.post("/api/subscribe")
async def subscribe_push(sub: PushSubscription, current_user: dict = Depends(get_current_user)):
    conn = get_db(); cursor = conn.cursor()
    cursor.execute("SELECT id FROM push_subscriptions WHERE endpoint = %s", (sub.endpoint,))
    if not cursor.fetchone():
        cursor.execute("INSERT INTO push_subscriptions (username, endpoint, p256dh, auth) VALUES (%s, %s, %s, %s)",
                       (current_user['username'], sub.endpoint, sub.keys['p256dh'], sub.keys['auth']))
        conn.commit()
    conn.close(); return {"msg": "Suscrito ok"}

@app.post("/api/test_push")
async def test_push(current_user: dict = Depends(get_current_user)):
    conn = get_db(); cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM push_subscriptions WHERE username = %s", (current_user['username'],))
    subs = cursor.fetchall(); conn.close()
    
    if not subs: raise HTTPException(status_code=400, detail="Dispositivo no suscrito a notificaciones")
    
    payload = {"title": "⚠️ Alerta de Reefer Pro", "body": "¡Las notificaciones Push están funcionando perfectamente!"}
    for s in subs:
        try:
            webpush(subscription_info={"endpoint": s['endpoint'], "keys": {"p256dh": s['p256dh'], "auth": s['auth']}},
                    data=json.dumps(payload), vapid_private_key=VAPID_PRIVATE_KEY, vapid_claims=VAPID_CLAIMS)
        except WebPushException as ex:
            print("Error enviando push:", repr(ex))
    return {"msg": "Enviado"}
@app.post("/api/save_settings")
async def save_settings(settings: DeviceSettings, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    
    # Si es cliente, verificamos que el equipo sea suyo
    if current_user['role'] == 'cliente':
        cursor.execute("SELECT id FROM user_devices JOIN users ON user_devices.user_id = users.id WHERE users.username = %s AND user_devices.device_id = %s", (current_user['username'], settings.device_id))
        if not cursor.fetchone():
            conn.close(); raise HTTPException(status_code=403, detail="No tienes acceso a este equipo")

    sql = """UPDATE device_config SET 
             setpoint = %s, tolerancia_temp = %s, tiempo_caliente = %s, 
             tiempo_apagado = %s, tiempo_offline = %s 
             WHERE device_id = %s"""
    cursor.execute(sql, (settings.setpoint, settings.tolerancia_temp, settings.tiempo_caliente, settings.tiempo_apagado, settings.tiempo_offline, settings.device_id))
    conn.commit()
    conn.close()
    return {"msg": "Configuración guardada exitosamente"}