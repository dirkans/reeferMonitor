from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timedelta
import mysql.connector
from jose import JWTError, jwt
from passlib.context import CryptContext
from typing import Optional
# --- CONFIGURACION ---
SECRET_KEY = "tu_secreto_super_seguro_cambialo"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

db_config = {
    'user': 'iot_user',
    'password': '062292',
    'host': '127.0.0.1',
    'database': 'reefer_iot'
}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
app = FastAPI()

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

class Token(BaseModel):
    access_token: str
    token_type: str

class UserCreate(BaseModel):
    username: str
    password: str

class UserReset(BaseModel):
    user_id: int
    new_password: str

class UserDelete(BaseModel):
    user_id: int

class DeviceAssign(BaseModel):
    username: str
    device_id: str

class DeviceDelete(BaseModel):
    device_id: str

class AssignmentAction(BaseModel):
    assignment_id: int

class RelayCommand(BaseModel):
    device_id: str
    relay_name: str 
    state: bool

class LecturaCompleta(BaseModel):
    device_id: str
    temp_return: float
    temp_supply: float
    temp_evap: float
    amp_r: float
    amp_s: float
    amp_t: float
    rssi: int
    real_comp: int
    real_evap: int
    real_cond: int
    real_heat: int
    real_reefer: int

def get_db(): return mysql.connector.connect(**db_config)
def verify_pass(p, h): return pwd_context.verify(p, h)
def get_hash(p): return pwd_context.hash(p)
def create_token(data: dict):
    to_encode = data.copy()
    to_encode.update({"exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None: raise HTTPException(status_code=401)
    except JWTError: raise HTTPException(status_code=401)
    return username

@app.get("/login", response_class=HTMLResponse)
async def ver_login(): return FileResponse("login.html")

@app.get("/panel", response_class=HTMLResponse)
async def ver_panel(): return FileResponse("panel.html")

@app.post("/token", response_model=Token)
async def login(form: OAuth2PasswordRequestForm = Depends()):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username = %s", (form.username,))
    user = cursor.fetchone()
    conn.close()
    if not user or not verify_pass(form.password, user['password_hash']):
        raise HTTPException(status_code=401)
    return {"access_token": create_token({"sub": user['username'], "admin": user['is_admin']}), "token_type": "bearer"}

@app.post("/api/datos")
async def recibir_datos_iot(d: LecturaCompleta):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        sql = """INSERT INTO lecturas 
                 (device_id, temperatura, temp_supply, temp_evap, amp_r, amp_s, amp_t, rssi, 
                  real_comp, real_evap, real_cond, real_heat, real_reefer) 
                 VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        vals = (d.device_id, d.temp_return, d.temp_supply, d.temp_evap, d.amp_r, d.amp_s, d.amp_t, d.rssi,
                d.real_comp, d.real_evap, d.real_cond, d.real_heat, d.real_reefer)
        cursor.execute(sql, vals)
        conn.commit()

        cursor.execute("SELECT * FROM device_config WHERE device_id = %s", (d.device_id,))
        config = cursor.fetchone()
        
        if not config:
            cursor.execute("INSERT INTO device_config (device_id) VALUES (%s)", (d.device_id,))
            conn.commit()
            config = {'relay_compresor':0, 'relay_evaporador':0, 'relay_condensador':0, 'relay_resistencia':0, 'relay_reefer':0}

    except Exception as e:
        print(f"Error IOT: {e}")
        return {"status": "error"}
    finally:
        conn.close()
    
    return {
        "status": "ok",
        "relays": {
            "comp": int(config['relay_compresor']),
            "evap": int(config['relay_evaporador']),
            "cond": int(config['relay_condensador']),
            "heat": int(config['relay_resistencia']),
            "reefer": int(config['relay_reefer'])
        }
    }

@app.post("/admin/control_relay")
async def control_relay(cmd: RelayCommand, current_user: str = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("SELECT is_admin FROM users WHERE username = %s", (current_user,))
    user = cursor.fetchone()
    if not user or not user['is_admin']:
        conn.close(); raise HTTPException(status_code=403, detail="Solo Admin")

    if cmd.relay_name != "reefer" and cmd.state == True:
        cursor.execute("SELECT relay_reefer FROM device_config WHERE device_id = %s", (cmd.device_id,))
        cfg = cursor.fetchone()
        if cfg and cfg['relay_reefer']:
            conn.close()
            raise HTTPException(status_code=400, detail="BLOQUEADO: Apaga el modo REEFER primero.")

    if cmd.relay_name == "reefer" and cmd.state == True:
        cursor.execute("""UPDATE device_config SET 
                          relay_compresor=0, relay_evaporador=0, relay_condensador=0, relay_resistencia=0 
                          WHERE device_id = %s""", (cmd.device_id,))

    col_name = f"relay_{cmd.relay_name}"
    sql = f"UPDATE device_config SET {col_name} = %s WHERE device_id = %s"
    cursor.execute(sql, (cmd.state, cmd.device_id))
    conn.commit()
    conn.close()
    return {"msg": "Comando enviado"}

# --- NUEVO ENDPOINT PARA BORRAR EQUIPOS ---
@app.post("/admin/delete_device")
async def delete_device(cmd: DeviceDelete, current_user: str = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    
    # 1. Verificar Admin
    cursor.execute("SELECT is_admin FROM users WHERE username = %s", (current_user,))
    user = cursor.fetchone()
    if not user or not user[0]: # user[0] es is_admin si usamos cursor normal o dict
        conn.close(); raise HTTPException(status_code=403, detail="Solo Admin")

    try:
        # Borrar asignaciones
        cursor.execute("DELETE FROM user_devices WHERE device_id = %s", (cmd.device_id,))
        # Borrar historial (Opcional, pero recomendado para limpiar)
        cursor.execute("DELETE FROM lecturas WHERE device_id = %s", (cmd.device_id,))
        # Borrar configuracion
        cursor.execute("DELETE FROM device_config WHERE device_id = %s", (cmd.device_id,))
        conn.commit()
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=400, detail=str(e))
        
    conn.close()
    return {"msg": "Equipo eliminado correctamente"}

@app.get("/api/estado_actual/{device_id}")
async def get_estado(device_id: str, current_user: str = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM lecturas WHERE device_id = %s ORDER BY fecha DESC LIMIT 1", (device_id,))
    lectura = cursor.fetchone()
    cursor.execute("SELECT * FROM device_config WHERE device_id = %s", (device_id,))
    config = cursor.fetchone()
    conn.close()
    return {"lectura": lectura, "config": config}

@app.get("/api/historial/{device_id}")
async def historial(
    device_id: str, 
    inicio: Optional[str] = None, 
    fin: Optional[str] = None, 
    current_user: str = Depends(get_current_user)
):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    # Si no hay fechas, traemos ultimas 24 horas
    if not inicio or not fin:
        # Limitamos a 2000 puntos para no explotar el grafico si hay muchos datos
        cursor.execute("""
            SELECT * FROM lecturas 
            WHERE device_id = %s 
            ORDER BY fecha DESC LIMIT 2000
        """, (device_id,))
    else:
        # Formato esperado: YYYY-MM-DD HH:MM
        cursor.execute("""
            SELECT * FROM lecturas 
            WHERE device_id = %s AND fecha BETWEEN %s AND %s 
            ORDER BY fecha ASC
        """, (device_id, inicio, fin))
        
    res = cursor.fetchall()
    conn.close()
    
    # Si no hubo filtro de fecha, invertimos para que el grafico vaya de izq a der cronologicamente
    if not inicio:
        return res[::-1] 
    return res

@app.get("/my/devices")
async def get_my_devices(current_user: str = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    if current_user == 'admin':
        query = "SELECT device_id, TIMESTAMPDIFF(SECOND, MAX(fecha), NOW()) as segundos_atras FROM lecturas GROUP BY device_id"
        cursor.execute(query)
    else:
        query = """
            SELECT d.device_id, TIMESTAMPDIFF(SECOND, MAX(l.fecha), NOW()) as segundos_atras
            FROM user_devices d 
            JOIN users u ON d.user_id = u.id 
            LEFT JOIN lecturas l ON d.device_id = l.device_id
            WHERE u.username = %s AND d.is_active = 1
            GROUP BY d.device_id
        """
        cursor.execute(query, (current_user,))
    
    devices = cursor.fetchall()
    conn.close()
    return devices

@app.get("/admin/users_list")
async def get_users_list(current_user: str = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, username, is_admin, created_at FROM users")
    users = cursor.fetchall()
    conn.close()
    return users

@app.post("/admin/reset_password")
async def reset_password(reset_data: UserReset, current_user: str = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    new_hash = get_hash(reset_data.new_password)
    try:
        cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (new_hash, reset_data.user_id))
        conn.commit()
    except Exception as e: raise HTTPException(status_code=400, detail=str(e))
    conn.close()
    return {"msg": "Clave actualizada"}

@app.post("/admin/delete_user")
async def delete_user(delete_data: UserDelete, current_user: str = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE id = %s", (delete_data.user_id,))
    target = cursor.fetchone()
    if target and target[0] == 'admin':
        conn.close()
        raise HTTPException(status_code=400, detail="No puedes borrar al admin")
    cursor.execute("DELETE FROM users WHERE id = %s", (delete_data.user_id,))
    conn.commit()
    conn.close()
    return {"msg": "Usuario eliminado"}

@app.get("/admin/assignments")
async def get_assignments(current_user: str = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    query = "SELECT ud.id, u.username, ud.device_id, ud.is_active FROM user_devices ud JOIN users u ON ud.user_id = u.id"
    cursor.execute(query)
    data = cursor.fetchall()
    conn.close()
    return data

@app.post("/admin/toggle_active")
async def toggle_active(action: AssignmentAction, current_user: str = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE user_devices SET is_active = NOT is_active WHERE id = %s", (action.assignment_id,))
    conn.commit()
    conn.close()
    return {"msg": "Estado actualizado"}

@app.post("/admin/delete_assignment")
async def delete_assignment(action: AssignmentAction, current_user: str = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM user_devices WHERE id = %s", (action.assignment_id,))
    conn.commit()
    conn.close()
    return {"msg": "Asignacion eliminada"}

@app.post("/admin/users")
async def create_user(new_user: UserCreate, current_user: str = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (new_user.username, get_hash(new_user.password)))
        conn.commit()
    except: raise HTTPException(status_code=400, detail="Error crear usuario")
    conn.close()
    return {"msg": "Usuario creado"}

@app.post("/admin/assign")
async def assign_device(assignment: DeviceAssign, current_user: str = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = %s", (assignment.username,))
    row = cursor.fetchone()
    if not row: raise HTTPException(status_code=404, detail="Usuario no existe")
    try:
        cursor.execute("INSERT INTO user_devices (user_id, device_id) VALUES (%s, %s)", (row[0], assignment.device_id))
        conn.commit()
    except: raise HTTPException(status_code=400, detail="Error asignar")
    conn.close()
    return {"msg": "Asignado"}