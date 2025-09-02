import os
import hashlib
import requests
import xml.etree.ElementTree as ET
from flask import Flask, request, jsonify
from datetime import datetime, timedelta
import json
import logging
import sys
import time

# =========================
# Configurar UTF-8
# =========================
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
os.environ['PYTHONIOENCODING'] = 'utf-8'

# =========================
# Logging
# =========================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('wechat_bot.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# =========================
# Flask App
# =========================
app = Flask(__name__)
app.config.update(
    JSON_AS_ASCII=False,
    JSONIFY_MIMETYPE='application/json; charset=utf-8',
    JSON_SORT_KEYS=False
)

# =========================
# Configuración
# =========================
class Config:
    def __init__(self):
        self.WECHAT_CONFIG = {
            'app_id': os.getenv('WECHAT_APP_ID'),
            'app_secret': os.getenv('WECHAT_APP_SECRET'),
            'token': os.getenv('WECHAT_TOKEN')
        }
        self.PORT = int(os.getenv('PORT', 5000))
        self.MAX_RETRIES = 3
        self.REQUEST_TIMEOUT = 8
        self._validate_config()

    def _validate_config(self):
        missing_wechat = [k for k, v in self.WECHAT_CONFIG.items() if not v]
        if missing_wechat:
            logger.error(f"Configuración WeChat faltante: {missing_wechat}")
        else:
            logger.info("Configuración WeChat cargada correctamente")

config = Config()

# =========================
# Estado global simplificado
# =========================
class AppState:
    def __init__(self):
        self.access_token = None
        self.token_expires_at = None

app_state = AppState()

# =========================
# Utilidades
# =========================
def ensure_utf8_string(text) -> str:
    """Asegurar que el texto sea UTF-8"""
    if text is None:
        return ""
    if isinstance(text, str):
        return text
    if isinstance(text, bytes):
        return text.decode('utf-8', errors='replace')
    return str(text)

# =========================
# WeChat API
# =========================
class WeChatAPI:
    @staticmethod
    def get_access_token() -> str:
        """Obtener access token de WeChat"""
        if (app_state.access_token and 
            app_state.token_expires_at and 
            datetime.now() < app_state.token_expires_at):
            return app_state.access_token
        
        try:
            url = "https://api.weixin.qq.com/cgi-bin/token"
            params = {
                'grant_type': 'client_credential',
                'appid': config.WECHAT_CONFIG['app_id'],
                'secret': config.WECHAT_CONFIG['app_secret']
            }
            
            response = requests.get(url, params=params, timeout=config.REQUEST_TIMEOUT)
            data = response.json()
            
            if 'access_token' in data:
                app_state.access_token = data['access_token']
                expires_in = int(data.get('expires_in', 7200))
                app_state.token_expires_at = datetime.now() + timedelta(seconds=expires_in - 300)
                logger.info("Access token renovado correctamente")
                return app_state.access_token
            else:
                logger.error(f"Error obteniendo access token: {data}")
                return None
                
        except Exception as e:
            logger.exception(f"Error en get_access_token: {e}")
            return None

    @staticmethod
    def send_message(to_user: str, message: str) -> bool:
        """Enviar mensaje de texto a usuario de WeChat"""
        token = WeChatAPI.get_access_token()
        if not token:
            logger.error("No se pudo obtener access_token")
            return False
        
        url = f"https://api.weixin.qq.com/cgi-bin/message/custom/send?access_token={token}"
        clean_message = ensure_utf8_string(message)
        
        # Limitar longitud del mensaje
        if len(clean_message) > 2000:
            clean_message = clean_message[:1990] + "\n\n[Mensaje truncado]"
        
        payload = {
            "touser": to_user,
            "msgtype": "text",
            "text": {"content": clean_message}
        }
        
        headers = {
            'Content-Type': 'application/json; charset=utf-8',
            'User-Agent': 'WeChat-SimpleBot/1.0'
        }
        
        for intento in range(config.MAX_RETRIES):
            try:
                resp = requests.post(
                    url, 
                    data=json.dumps(payload, ensure_ascii=False).encode('utf-8'),
                    headers=headers, 
                    timeout=config.REQUEST_TIMEOUT
                )
                result = resp.json()
                
                if result.get('errcode', 0) == 0:
                    logger.info(f"Mensaje enviado exitosamente a {to_user}")
                    return True
                else:
                    logger.warning(f"Error enviando mensaje (intento {intento+1}): {result}")
                    if intento < config.MAX_RETRIES - 1:
                        time.sleep(0.5 * (intento + 1))
                        
            except Exception as e:
                logger.exception(f"Error en intento {intento+1} enviando mensaje: {e}")
                if intento < config.MAX_RETRIES - 1:
                    time.sleep(0.5 * (intento + 1))
        
        logger.error(f"Fallo definitivo enviando mensaje a {to_user}")
        return False

    @staticmethod
    def verify_signature(signature: str, timestamp: str, nonce: str) -> bool:
        """Verificar firma del webhook de WeChat"""
        token = config.WECHAT_CONFIG.get('token')
        if not token:
            return False
        
        tmp_list = [token, timestamp, nonce]
        tmp_list.sort()
        tmp_str = ''.join(tmp_list)
        computed_signature = hashlib.sha1(tmp_str.encode('utf-8')).hexdigest()
        
        return computed_signature == signature

    @staticmethod
    def parse_xml_message(xml_data) -> dict:
        """Parsear mensaje XML de WeChat"""
        try:
            if isinstance(xml_data, bytes):
                xml_data = xml_data.decode('utf-8')
            
            root = ET.fromstring(ensure_utf8_string(xml_data))
            message = {}
            
            for child in root:
                message[child.tag] = ensure_utf8_string(child.text or "")
            
            return message
            
        except Exception as e:
            logger.exception(f"Error parsing XML: {e}")
            return {}

wechat_api = WeChatAPI()

# =========================
# Handlers de mensajes
# =========================
def handle_text_message(from_user: str, content: str) -> None:
    """Manejar mensaje de texto"""
    try:
        logger.info(f"Procesando mensaje de texto de {from_user}: {content[:50]}...")
        
        # Respuesta simple de eco con ID del chat
        response = f"Echo: {content} | Chat ID: {from_user}"
        
        # Enviar respuesta
        success = wechat_api.send_message(from_user, response)
        if not success:
            logger.error(f"No se pudo enviar respuesta a {from_user}")
            
    except Exception as e:
        logger.exception(f"Error manejando mensaje de texto: {e}")
        wechat_api.send_message(from_user, "Error procesando tu mensaje")

def handle_image_message(from_user: str, media_id: str) -> None:
    """Manejar mensaje de imagen"""
    try:
        logger.info(f"Procesando imagen de {from_user}, media_id: {media_id}")
        
        # Respuesta simple con info de la imagen y chat ID
        response = f"Imagen recibida: {media_id[:8]}... | Chat ID: {from_user}"
        
        # Enviar respuesta
        success = wechat_api.send_message(from_user, response)
        if not success:
            logger.error(f"No se pudo enviar respuesta de imagen a {from_user}")
            
    except Exception as e:
        logger.exception(f"Error manejando imagen: {e}")
        wechat_api.send_message(from_user, "Error procesando tu imagen")

def handle_subscribe_event(from_user: str) -> None:
    """Manejar evento de suscripción"""
    welcome_message = """¡Bienvenido a nuestro bot de WeChat!

Este es un bot simple que puede:
- Recibir y responder mensajes de texto
- Procesar imágenes
- Mantener un historial básico de conversación

Envía cualquier mensaje para probar."""
    
    wechat_api.send_message(from_user, welcome_message)

# =========================
# Endpoints
# =========================
@app.route('/wechat', methods=['GET', 'POST'])
def wechat_endpoint():
    """Endpoint principal del webhook de WeChat"""
    if request.method == 'GET':
        # Verificación del webhook
        signature = request.args.get('signature', '')
        timestamp = request.args.get('timestamp', '')
        nonce = request.args.get('nonce', '')
        echostr = request.args.get('echostr', '')
        
        if wechat_api.verify_signature(signature, timestamp, nonce):
            logger.info("Webhook verificado correctamente")
            return echostr
        else:
            logger.warning("Fallo en verificación de webhook")
            return 'Forbidden', 403
    
    # Procesamiento de mensajes POST
    try:
        xml_data = request.get_data()
        logger.info(f"Datos XML recibidos: {len(xml_data)} bytes")
        
        message = wechat_api.parse_xml_message(xml_data)
        if not message:
            logger.warning("No se pudo parsear el mensaje XML")
            return ''
        
        msg_type = message.get('MsgType', '')
        from_user = message.get('FromUserName', '')
        
        logger.info(f"Mensaje recibido - Tipo: {msg_type}, Usuario: {from_user}")
        
        if msg_type == 'text':
            content = message.get('Content', '')
            handle_text_message(from_user, content)
            
        elif msg_type == 'image':
            media_id = message.get('MediaId', '')
            handle_image_message(from_user, media_id)
            
        elif msg_type == 'event':
            event = message.get('Event', '').upper()
            if event == 'SUBSCRIBE':
                handle_subscribe_event(from_user)
        
        return ''
        
    except Exception as e:
        logger.exception(f"Error procesando mensaje POST: {e}")
        return ''

@app.route('/health', methods=['GET'])
def health_check():
    """Endpoint de verificación de salud"""
    try:
        status_data = {
            'status': 'OK',
            'timestamp': datetime.now().isoformat(),
            'wechat_config': {
                'app_id_configured': bool(config.WECHAT_CONFIG['app_id']),
                'app_secret_configured': bool(config.WECHAT_CONFIG['app_secret']),
                'token_configured': bool(config.WECHAT_CONFIG['token'])
            },
            'access_token_valid': bool(app_state.access_token)
        }
        
        response = jsonify(status_data)
        response.headers['Content-Type'] = 'application/json; charset=utf-8'
        return response
        
    except Exception as e:
        logger.exception(f"Error en health check: {e}")
        return jsonify({'status': 'ERROR', 'error': str(e)}), 500

@app.route('/send', methods=['POST'])
def send_message_endpoint():
    """Endpoint para enviar mensajes programáticamente"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        message = data.get('message')
        
        if not user_id or not message:
            return jsonify({'error': 'user_id y message son requeridos'}), 400
        
        success = wechat_api.send_message(user_id, message)
        
        if success:
            return jsonify({'status': 'sent', 'user_id': user_id, 'message': message})
        else:
            return jsonify({'error': 'No se pudo enviar el mensaje'}), 500
            
    except Exception as e:
        logger.exception(f"Error enviando mensaje: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/', methods=['GET'])
def index():
    """Página principal"""
    return '''
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Bot WeChat Simple</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
            .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #2c3e50; text-align: center; }
            .status { background-color: #e8f5e8; padding: 15px; border-radius: 5px; margin: 20px 0; }
            .endpoint { background-color: #f8f9fa; padding: 10px; border-radius: 5px; margin: 10px 0; font-family: monospace; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🤖 Bot WeChat Simple</h1>
            <div class="status">
                <strong>✅ Servicio activo</strong>
                <p>Bot básico de WeChat con webhook configurado y envío de mensajes.</p>
            </div>
            
            <h3>Funcionalidades:</h3>
            <ul>
                <li>✅ Webhook verificado para WeChat</li>
                <li>✅ Recepción de mensajes de texto e imágenes</li>
                <li>✅ Envío de respuestas automáticas</li>
                <li>✅ Historial básico de conversaciones</li>
                <li>✅ Mensaje de bienvenida en suscripción</li>
            </ul>
            
            <h3>Endpoints disponibles:</h3>
            <div class="endpoint">GET /wechat - Verificación del webhook</div>
            <div class="endpoint">POST /wechat - Recepción de mensajes</div>
            <div class="endpoint">GET /health - Estado del servicio</div>
            <div class="endpoint">GET /users/{user_id}/history - Historial de usuario</div>
            <div class="endpoint">POST /send - Enviar mensaje programáticamente</div>
        </div>
    </body>
    </html>
    '''

# =========================
# Main
# =========================
if __name__ == '__main__':
    logger.info("🚀 Iniciando Bot WeChat Simple...")
    
    # Verificar configuración
    missing_config = [k for k, v in config.WECHAT_CONFIG.items() if not v]
    if missing_config:
        logger.error(f"❌ Configuración de WeChat faltante: {missing_config}")
    else:
        logger.info("✅ Configuración de WeChat completa")
    
    # Verificar access token
    token = wechat_api.get_access_token()
    if token:
        logger.info("✅ Access token obtenido correctamente")
    else:
        logger.error("❌ No se pudo obtener access token - verifica configuración")
    
    # Iniciar servidor
    port = config.PORT
    logger.info(f"🌐 Iniciando servidor en puerto {port}")
    logger.info("📋 Endpoints: /, /health, /users/<user_id>/history, /send, /wechat")
    
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)