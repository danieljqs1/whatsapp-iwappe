# CLAUDE.md

Este archivo proporciona orientación a Claude Code (claude.ai/code) al trabajar con código en este repositorio.

## Comandos comunes de desarrollo

### Instalación de dependencias
```bash
pip install -r requirements.txt
```

### Ejecutar la aplicación
```bash
python main.py
```

### Variables de entorno requeridas
```bash
# WhatsApp Business API
WHATSAPP_ACCESS_TOKEN=token_de_acceso
WHATSAPP_VERIFY_TOKEN=token_de_verificacion  
WHATSAPP_APP_SECRET=secreto_de_app
WHATSAPP_PHONE_NUMBER_ID=id_del_numero_de_telefono

# AWS AgentCore
AWS_AGENT_ARN=arn:aws:bedrock-agentcore:us-east-1:979565263676:runtime/main-ZQLI8JE0PH
AWS_REGION=us-east-1

# Servidor
PORT=5000
```

## Arquitectura del proyecto

### Componentes principales

**main.py**: Aplicación Flask principal que implementa:
- **WhatsAppAPI**: Clase para interactuar con WhatsApp Business API, soporta mensajes de texto, botones interactivos, listas y media
- **Config**: Gestión centralizada de configuración con validación
- **Webhook handlers**: Procesamiento de mensajes entrantes de WhatsApp (texto, imágenes, botones, listas)
- **Procesamiento asíncrono**: Los mensajes se procesan en threads separados para evitar duplicados

**aws_agent.py**: Integración con AWS AgentCore que maneja:
- **AWSAgentCore**: Cliente para invocar agentes de AWS Bedrock AgentCore
- **Gestión de sesiones**: Mantiene contexto conversacional usando session IDs con prefijo "whatsapp_"
- **Parsing inteligente**: Procesa respuestas JSON estructuradas y texto plano

### Flujo de mensajes

1. **Recepción**: WhatsApp envía webhook POST a `/webhook`
2. **Validación**: Verificación de firma HMAC si app_secret está configurado
3. **Procesamiento async**: Mensaje enviado a thread background
4. **AWS AgentCore**: Invocación del agente con session ID único por usuario
5. **Respuesta inteligente**: Procesamiento de diferentes tipos de respuesta (texto, botones, listas, media)
6. **Envío**: Respuesta formateada enviada de vuelta via WhatsApp API

### Endpoints disponibles

- `GET /`: Página de estado con información del servicio
- `GET /webhook`: Verificación del webhook de WhatsApp
- `POST /webhook`: Recepción y procesamiento de mensajes
- `GET /health`: Estado detallado del servicio y configuración

### Gestión de errores y logging

- Logging estructurado a archivo `whatsapp_bot.log` y consola
- Reintentos automáticos para llamadas a WhatsApp API (MAX_RETRIES=3)
- Timeouts configurables (REQUEST_TIMEOUT=8s)
- Modo fallback si AWS AgentCore no está disponible

### Tipos de mensaje soportados

- **Texto**: Mensajes de texto plano
- **Imágenes**: Recepción de imágenes (convertidas a texto "He enviado una imagen")
- **Botones interactivos**: Máximo 3 botones por mensaje
- **Listas**: Secciones con máximo 10 opciones cada una
- **Media con botones**: Combinación de imagen + botones interactivos

## Notas técnicas

- Usa UTF-8 para todo el manejo de texto
- Session IDs usan formato "whatsapp_user_{numero}_session" para cumplir con mínimo de 33 caracteres de AWS
- Límites de WhatsApp: mensajes de 4096 caracteres, títulos de botón 20 caracteres
- Configuración de Flask para JSON sin escape ASCII