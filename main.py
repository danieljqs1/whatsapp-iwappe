import os
import hashlib
import requests
import hmac
from flask import Flask, request, jsonify
from datetime import datetime, timedelta
import json
import logging
import sys
import time
import threading
from aws_agent import AWSAgentCore

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
        logging.FileHandler('whatsapp_bot.log', encoding='utf-8'),
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
        self.WHATSAPP_CONFIG = {
            'access_token': os.getenv('WHATSAPP_ACCESS_TOKEN'),
            'verify_token': os.getenv('WHATSAPP_VERIFY_TOKEN'),
            'app_secret': os.getenv('WHATSAPP_APP_SECRET'),
            'phone_number_id': os.getenv('WHATSAPP_PHONE_NUMBER_ID')
        }
        self.AWS_CONFIG = {
            'agent_arn': os.getenv('AWS_AGENT_ARN', 'arn:aws:bedrock-agentcore:us-east-1:979565263676:runtime/main-ZQLI8JE0PH'),
            'region': os.getenv('AWS_REGION', 'us-east-1')
        }
        self.PORT = int(os.getenv('PORT', 5000))
        self.MAX_RETRIES = 3
        self.REQUEST_TIMEOUT = 8
        self._validate_config()

    def _validate_config(self):
        missing_whatsapp = [k for k, v in self.WHATSAPP_CONFIG.items() if not v]
        if missing_whatsapp:
            logger.error(f"Configuración WhatsApp faltante: {missing_whatsapp}")
        else:
            logger.info("Configuración WhatsApp cargada correctamente")
        
        if self.AWS_CONFIG['agent_arn']:
            logger.info(f"Configuración AWS AgentCore: {self.AWS_CONFIG['agent_arn'][:50]}...")
        else:
            logger.warning("AWS_AGENT_ARN no configurado, usando valor por defecto")

config = Config()

# =========================
# AWS AgentCore
# =========================
aws_agent = AWSAgentCore(
    agent_arn=config.AWS_CONFIG['agent_arn'],
    region=config.AWS_CONFIG['region']
)

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
# WhatsApp API
# =========================
class WhatsAppAPI:
    @staticmethod
    def send_text_message(to_user: str, message: str) -> bool:
        """Enviar mensaje de texto a usuario de WhatsApp"""
        if not config.WHATSAPP_CONFIG['access_token']:
            logger.error("Access token de WhatsApp no configurado")
            return False
        
        url = f"https://graph.facebook.com/v18.0/{config.WHATSAPP_CONFIG['phone_number_id']}/messages"
        clean_message = ensure_utf8_string(message)
        
        # Limitar longitud del mensaje
        if len(clean_message) > 4096:
            clean_message = clean_message[:4090] + "..."
        
        payload = {
            "messaging_product": "whatsapp",
            "to": to_user,
            "type": "text",
            "text": {"body": clean_message}
        }
        
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {config.WHATSAPP_CONFIG["access_token"]}'
        }
        
        for intento in range(config.MAX_RETRIES):
            try:
                resp = requests.post(
                    url, 
                    json=payload,
                    headers=headers, 
                    timeout=config.REQUEST_TIMEOUT
                )
                
                if resp.status_code == 200:
                    logger.info(f"Mensaje enviado exitosamente a {to_user}")
                    return True
                else:
                    logger.warning(f"Error enviando mensaje (intento {intento+1}): {resp.status_code} - {resp.text}")
                    if intento < config.MAX_RETRIES - 1:
                        time.sleep(0.5 * (intento + 1))
                        
            except Exception as e:
                logger.exception(f"Error en intento {intento+1} enviando mensaje: {e}")
                if intento < config.MAX_RETRIES - 1:
                    time.sleep(0.5 * (intento + 1))
        
        logger.error(f"Fallo definitivo enviando mensaje a {to_user}")
        return False

    @staticmethod
    def send_interactive_buttons(to_user: str, message_data: dict) -> bool:
        """Enviar mensaje con botones interactivos"""
        if not config.WHATSAPP_CONFIG['access_token']:
            logger.error("Access token de WhatsApp no configurado")
            return False
        
        url = f"https://graph.facebook.com/v18.0/{config.WHATSAPP_CONFIG['phone_number_id']}/messages"
        
        buttons = []
        for btn in message_data.get('buttons', [])[:3]:  # WhatsApp permite máximo 3 botones
            buttons.append({
                "type": "reply",
                "reply": {
                    "id": btn.get('id', ''),
                    "title": btn.get('title', '')[:20]  # Máximo 20 caracteres
                }
            })
        
        payload = {
            "messaging_product": "whatsapp",
            "to": to_user,
            "type": "interactive",
            "interactive": {
                "type": "button",
                "body": {"text": message_data.get('message', '')},
                "action": {"buttons": buttons}
            }
        }
        
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {config.WHATSAPP_CONFIG["access_token"]}'
        }
        
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=config.REQUEST_TIMEOUT)
            if resp.status_code == 200:
                logger.info(f"Botones enviados exitosamente a {to_user}")
                return True
            else:
                logger.warning(f"Error enviando botones: {resp.status_code} - {resp.text}")
                return False
        except Exception as e:
            logger.exception(f"Error enviando botones: {e}")
            return False

    @staticmethod
    def send_list_message(to_user: str, message_data: dict) -> bool:
        """Enviar mensaje con lista de opciones"""
        if not config.WHATSAPP_CONFIG['access_token']:
            logger.error("Access token de WhatsApp no configurado")
            return False
        
        url = f"https://graph.facebook.com/v18.0/{config.WHATSAPP_CONFIG['phone_number_id']}/messages"
        
        sections = []
        for section in message_data.get('list_sections', []):
            rows = []
            for row in section.get('rows', [])[:10]:  # Máximo 10 opciones por sección
                rows.append({
                    "id": row.get('id', ''),
                    "title": row.get('title', '')[:24],  # Máximo 24 caracteres
                    "description": row.get('description', '')[:72]  # Máximo 72 caracteres
                })
            
            if rows:
                sections.append({
                    "title": section.get('title', '')[:24],
                    "rows": rows
                })
        
        payload = {
            "messaging_product": "whatsapp",
            "to": to_user,
            "type": "interactive",
            "interactive": {
                "type": "list",
                "body": {"text": message_data.get('message', '')},
                "action": {
                    "button": "Ver opciones",
                    "sections": sections
                }
            }
        }
        
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {config.WHATSAPP_CONFIG["access_token"]}'
        }
        
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=config.REQUEST_TIMEOUT)
            if resp.status_code == 200:
                logger.info(f"Lista enviada exitosamente a {to_user}")
                return True
            else:
                logger.warning(f"Error enviando lista: {resp.status_code} - {resp.text}")
                return False
        except Exception as e:
            logger.exception(f"Error enviando lista: {e}")
            return False

    @staticmethod
    def send_media_message(to_user: str, message_data: dict) -> bool:
        """Enviar mensaje con imagen"""
        if not config.WHATSAPP_CONFIG['access_token']:
            logger.error("Access token de WhatsApp no configurado")
            return False
        
        url = f"https://graph.facebook.com/v18.0/{config.WHATSAPP_CONFIG['phone_number_id']}/messages"
        
        media = message_data.get('media', {})
        media_type = media.get('type', 'image')
        
        payload = {
            "messaging_product": "whatsapp",
            "to": to_user,
            "type": media_type,
            media_type: {
                "link": media.get('url', ''),
                "caption": media.get('caption', '')[:1024]  # Máximo 1024 caracteres para caption
            }
        }
        
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {config.WHATSAPP_CONFIG["access_token"]}'
        }
        
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=config.REQUEST_TIMEOUT)
            if resp.status_code == 200:
                logger.info(f"Media enviado exitosamente a {to_user}")
                return True
            else:
                logger.warning(f"Error enviando media: {resp.status_code} - {resp.text}")
                return False
        except Exception as e:
            logger.exception(f"Error enviando media: {e}")
            return False

    @staticmethod
    def verify_webhook(verify_token: str, mode: str, challenge: str) -> str:
        """Verificar webhook de WhatsApp"""
        if mode == "subscribe" and verify_token == config.WHATSAPP_CONFIG['verify_token']:
            logger.info("Webhook verificado correctamente")
            return challenge
        else:
            logger.warning("Fallo en verificación de webhook")
            return None

    @staticmethod
    def verify_signature(payload: bytes, signature: str) -> bool:
        """Verificar firma del payload de WhatsApp"""
        if not config.WHATSAPP_CONFIG['app_secret']:
            logger.warning("App secret no configurado, saltando verificación de firma")
            return True
        
        try:
            expected_signature = hmac.new(
                config.WHATSAPP_CONFIG['app_secret'].encode('utf-8'),
                payload,
                hashlib.sha256
            ).hexdigest()
            
            # Remover 'sha256=' del inicio si está presente
            signature = signature.replace('sha256=', '')
            
            return hmac.compare_digest(expected_signature, signature)
        except Exception as e:
            logger.exception(f"Error verificando firma: {e}")
            return False

whatsapp_api = WhatsAppAPI()

# =========================
# Procesador de respuestas del agente
# =========================
def process_agent_response(to_user: str, agent_response: dict) -> bool:
    """Procesar respuesta del agente y enviar mensaje apropiado"""
    try:
        response_type = agent_response.get('response_type', 'text')
        
        if response_type == 'text':
            return whatsapp_api.send_text_message(to_user, agent_response.get('message', ''))
        
        elif response_type == 'buttons':
            return whatsapp_api.send_interactive_buttons(to_user, agent_response)
        
        elif response_type == 'list':
            return whatsapp_api.send_list_message(to_user, agent_response)
        
        elif response_type in ['media', 'image', 'media_with_buttons']:
            # Primero enviar la imagen
            success = whatsapp_api.send_media_message(to_user, agent_response)
            
            # Si hay botones, enviarlos después
            if success and agent_response.get('buttons'):
                time.sleep(1)  # Pequeña pausa entre mensajes
                button_data = {
                    'message': agent_response.get('message', '¿Qué te gustaría hacer?'),
                    'buttons': agent_response.get('buttons', [])
                }
                whatsapp_api.send_interactive_buttons(to_user, button_data)
            
            return success
        
        else:
            logger.warning(f"Tipo de respuesta no soportado: {response_type}")
            return whatsapp_api.send_text_message(to_user, agent_response.get('message', 'Error procesando respuesta'))
    
    except Exception as e:
        logger.exception(f"Error procesando respuesta del agente: {e}")
        return whatsapp_api.send_text_message(to_user, "Error procesando tu solicitud")

# =========================
# Handlers de mensajes
# =========================
def process_text_message_async(from_user: str, content: str) -> None:
    """Procesar mensaje de texto de forma asíncrona"""
    try:
        logger.info(f"Procesando mensaje de texto en background de {from_user}: {content[:50]}...")
        
        if aws_agent.is_available():
            session_id = f"whatsapp_{from_user}"
            logger.info(f"Invocando AWS AgentCore para respuesta con session ID: {session_id}")
            agent_response = aws_agent.invoke_agent(content, session_id=session_id)
            
            if agent_response and isinstance(agent_response, dict):
                logger.info("Respuesta JSON generada por AWS AgentCore")
                success = process_agent_response(from_user, agent_response)
            elif agent_response:
                # Si es string, tratarlo como mensaje de texto simple
                logger.info("Respuesta de texto generada por AWS AgentCore")
                success = whatsapp_api.send_text_message(from_user, str(agent_response))
            else:
                logger.warning("AWS AgentCore no devolvió respuesta, usando fallback")
                success = whatsapp_api.send_text_message(from_user, f"Lo siento, no pude procesar tu mensaje en este momento.")
        else:
            # Fallback si AWS AgentCore no está disponible
            response = f"Echo: {content} | Chat ID: {from_user}"
            success = whatsapp_api.send_text_message(from_user, response)
            logger.warning("AWS AgentCore no disponible, usando modo eco")
        
        if not success:
            logger.error(f"No se pudo enviar respuesta a {from_user}")
            
    except Exception as e:
        logger.exception(f"Error procesando mensaje de texto en background: {e}")
        whatsapp_api.send_text_message(from_user, "Error procesando tu mensaje")

def handle_text_message(from_user: str, content: str) -> None:
    """Manejar mensaje de texto - procesamiento async"""
    try:
        logger.info(f"Recibido mensaje de texto de {from_user}: {content[:50]}...")
        
        # Procesar mensaje en background thread
        thread = threading.Thread(
            target=process_text_message_async,
            args=(from_user, content),
            daemon=True
        )
        thread.start()
        logger.info("Mensaje enviado a procesamiento en background")
            
    except Exception as e:
        logger.exception(f"Error manejando mensaje de texto: {e}")

def handle_image_message(from_user: str, media_id: str) -> None:
    """Manejar mensaje de imagen"""
    try:
        logger.info(f"Recibida imagen de {from_user}, media_id: {media_id}")
        
        # Para imágenes, simular que el usuario envió un mensaje
        simulated_message = "He enviado una imagen"
        handle_text_message(from_user, simulated_message)
            
    except Exception as e:
        logger.exception(f"Error manejando imagen: {e}")

def handle_button_response(from_user: str, button_id: str, button_text: str) -> None:
    """Manejar respuesta de botón"""
    try:
        logger.info(f"Botón presionado por {from_user}: {button_id} - {button_text}")
        
        # Tratar la respuesta del botón como mensaje de texto
        handle_text_message(from_user, button_text)
            
    except Exception as e:
        logger.exception(f"Error manejando botón: {e}")

def handle_list_response(from_user: str, list_id: str, list_title: str) -> None:
    """Manejar respuesta de lista"""
    try:
        logger.info(f"Opción de lista seleccionada por {from_user}: {list_id} - {list_title}")
        
        # Tratar la respuesta de lista como mensaje de texto
        handle_text_message(from_user, list_title)
            
    except Exception as e:
        logger.exception(f"Error manejando lista: {e}")

# =========================
# Endpoints
# =========================
@app.route('/webhook', methods=['GET', 'POST'])
def webhook():
    """Endpoint principal del webhook de WhatsApp"""
    if request.method == 'GET':
        # Verificación del webhook
        mode = request.args.get('hub.mode')
        token = request.args.get('hub.verify_token')
        challenge = request.args.get('hub.challenge')
        
        result = whatsapp_api.verify_webhook(token, mode, challenge)
        if result:
            return result
        else:
            return 'Forbidden', 403
    
    # Procesamiento de mensajes POST
    try:
        # Verificar firma si está configurado app_secret
        signature = request.headers.get('X-Hub-Signature-256', '')
        if config.WHATSAPP_CONFIG['app_secret'] and not whatsapp_api.verify_signature(request.get_data(), signature):
            logger.warning("Firma inválida en webhook")
            return 'Unauthorized', 401
        
        data = request.get_json()
        if not data:
            return 'OK'
        
        logger.info(f"Webhook data recibido: {json.dumps(data, indent=2)}")
        
        # Procesar entradas de WhatsApp
        for entry in data.get('entry', []):
            for change in entry.get('changes', []):
                value = change.get('value', {})
                
                # Procesar mensajes
                for message in value.get('messages', []):
                    from_user = message.get('from', '')
                    msg_type = message.get('type', '')
                    
                    if msg_type == 'text':
                        content = message.get('text', {}).get('body', '')
                        handle_text_message(from_user, content)
                    
                    elif msg_type == 'image':
                        media_id = message.get('image', {}).get('id', '')
                        handle_image_message(from_user, media_id)
                    
                    elif msg_type == 'interactive':
                        interactive = message.get('interactive', {})
                        if interactive.get('type') == 'button_reply':
                            button_reply = interactive.get('button_reply', {})
                            button_id = button_reply.get('id', '')
                            button_text = button_reply.get('title', '')
                            handle_button_response(from_user, button_id, button_text)
                        
                        elif interactive.get('type') == 'list_reply':
                            list_reply = interactive.get('list_reply', {})
                            list_id = list_reply.get('id', '')
                            list_title = list_reply.get('title', '')
                            handle_list_response(from_user, list_id, list_title)
        
        return 'OK'
        
    except Exception as e:
        logger.exception(f"Error procesando webhook: {e}")
        return 'OK'  # Siempre devolver OK para evitar reenvíos

@app.route('/health', methods=['GET'])
def health_check():
    """Endpoint de verificación de salud"""
    try:
        status_data = {
            'status': 'OK',
            'timestamp': datetime.now().isoformat(),
            'whatsapp_config': {
                'access_token_configured': bool(config.WHATSAPP_CONFIG['access_token']),
                'verify_token_configured': bool(config.WHATSAPP_CONFIG['verify_token']),
                'app_secret_configured': bool(config.WHATSAPP_CONFIG['app_secret']),
                'phone_number_id_configured': bool(config.WHATSAPP_CONFIG['phone_number_id'])
            },
            'aws_agent_available': aws_agent.is_available() if aws_agent else False
        }
        
        response = jsonify(status_data)
        response.headers['Content-Type'] = 'application/json; charset=utf-8'
        return response
        
    except Exception as e:
        logger.exception(f"Error en health check: {e}")
        return jsonify({'status': 'ERROR', 'error': str(e)}), 500

@app.route('/', methods=['GET'])
def index():
    """Página principal"""
    return '''
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Bot WhatsApp con AWS AgentCore</title>
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
            <h1>🤖 Bot WhatsApp con AWS AgentCore</h1>
            <div class="status">
                <strong>✅ Servicio activo</strong>
                <p>Bot de WhatsApp con webhook configurado, integración con AWS AgentCore y soporte para elementos interactivos.</p>
            </div>
            
            <h3>Funcionalidades:</h3>
            <ul>
                <li>✅ Webhook verificado para WhatsApp Business API</li>
                <li>✅ Recepción de mensajes de texto e imágenes</li>
                <li>✅ Integración con AWS AgentCore/Bedrock</li>
                <li>✅ Botones interactivos</li>
                <li>✅ Listas de opciones</li>
                <li>✅ Envío de imágenes con botones</li>
                <li>✅ Respuestas JSON estructuradas</li>
            </ul>
            
            <h3>Endpoints disponibles:</h3>
            <div class="endpoint">GET /webhook - Verificación del webhook</div>
            <div class="endpoint">POST /webhook - Recepción de mensajes</div>
            <div class="endpoint">GET /health - Estado del servicio</div>
        </div>
    </body>
    </html>
    '''

# =========================
# Main
# =========================
if __name__ == '__main__':
    logger.info("🚀 Iniciando Bot WhatsApp con AWS AgentCore...")
    
    # Verificar configuración
    missing_config = [k for k, v in config.WHATSAPP_CONFIG.items() if not v]
    if missing_config:
        logger.error(f"❌ Configuración de WhatsApp faltante: {missing_config}")
    else:
        logger.info("✅ Configuración de WhatsApp completa")
    
    # Verificar AWS AgentCore
    if aws_agent and aws_agent.is_available():
        logger.info("✅ AWS AgentCore disponible")
    else:
        logger.error("❌ AWS AgentCore no disponible - usando modo fallback")
    
    # Iniciar servidor
    port = config.PORT
    logger.info(f"🌐 Iniciando servidor en puerto {port}")
    logger.info("📋 Endpoints: /, /health, /webhook")
    
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)