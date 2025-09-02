import json
import boto3
import logging
from typing import Optional

logger = logging.getLogger(__name__)

class AWSAgentCore:
    def __init__(self, agent_arn: str, region: str = "us-east-1"):
        """
        Inicializar cliente de AWS AgentCore
        
        Args:
            agent_arn: ARN del agente de AgentCore
            region: Región de AWS (por defecto us-east-1)
        """
        self.agent_arn = agent_arn
        self.region = region
        
        try:
            self.agent_core_client = boto3.client(
                'bedrock-agentcore',
                region_name=region
            )
            logger.info(f"Cliente AWS AgentCore inicializado correctamente para región {region}")
        except Exception as e:
            logger.error(f"Error inicializando cliente AWS AgentCore: {e}")
            self.agent_core_client = None
    
    def invoke_agent(self, prompt: str) -> Optional[str]:
        """
        Invocar el agente de AgentCore con un prompt
        
        Args:
            prompt: Texto de entrada para el agente
            
        Returns:
            Respuesta del agente o None si hay error
        """
        if not self.agent_core_client:
            logger.error("Cliente AWS AgentCore no inicializado")
            return None
            
        if not prompt or not prompt.strip():
            logger.warning("Prompt vacío recibido")
            return None
            
        try:
            # Preparar payload
            payload = json.dumps({"prompt": prompt.strip()}).encode()
            
            logger.info(f"Invocando agente con prompt: {prompt[:50]}...")
            
            # Invocar agente
            response = self.agent_core_client.invoke_agent_runtime(
                agentRuntimeArn=self.agent_arn,
                payload=payload
            )
            
            # Procesar respuesta
            content = []
            for chunk in response.get("response", []):
                content.append(chunk.decode('utf-8'))
            
            if content:
                full_response = ''.join(content)
                try:
                    # Intentar parsear como JSON
                    parsed_response = json.loads(full_response)
                    logger.info("Respuesta del agente obtenida exitosamente")
                    return str(parsed_response)
                except json.JSONDecodeError:
                    # Si no es JSON válido, devolver como texto plano
                    logger.info("Respuesta del agente obtenida como texto plano")
                    return full_response
            else:
                logger.warning("Respuesta vacía del agente")
                return None
                
        except Exception as e:
            logger.exception(f"Error invocando agente AWS: {e}")
            return None
    
    def is_available(self) -> bool:
        """
        Verificar si el cliente está disponible
        
        Returns:
            True si el cliente está inicializado correctamente
        """
        return self.agent_core_client is not None