#!/usr/bin/env python3
import asyncio
import logging
import random
import string
from datetime import datetime
from typing import Dict

LOG_FILE = '/host-logs/modbus/modbus.log'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Simulated industrial device identity
class DeviceProfile:
    def __init__(self, profile_type: str):
        self.profile_type = profile_type
        self.serial = self._generate_serial()
        self.firmware = self._generate_firmware()
        self.device_info = self._create_device_info()
        
    def _generate_serial(self) -> str:
        if self.profile_type == "siemens":
            return f"S7-{random.randint(100000, 999999)}"
        else:
            return f"M340-{random.randint(10000, 99999)}-{random.choice(string.ascii_uppercase)}"
    
    def _generate_firmware(self) -> str:
        if self.profile_type == "siemens":
            major = random.randint(3, 4)
            minor = random.randint(0, 9)
            patch = random.randint(0, 99)
            return f"V{major}.{minor}.{patch}"
        else:
            return f"V{random.randint(2, 3)}.{random.randint(10, 30)}"
    
    def _create_device_info(self) -> Dict:
        if self.profile_type == "siemens":
            return {
                "VendorName": "Siemens AG",
                "ProductCode": "S7-1200",
                "VendorUrl": "http://www.siemens.com/",
                "ProductName": "SIMATIC S7-1200",
                "ModelName": f"CPU 1214C AC/DC/Rly",
                "MajorMinorRevision": self.firmware,
                "SerialNumber": self.serial,
                "DeviceName": f"PLC-{self.serial[-6:]}"
            }
        else:
            return {
                "VendorName": "Schneider Electric",
                "ProductCode": "M340",
                "VendorUrl": "http://www.schneider-electric.com/",
                "ProductName": "Modicon M340",
                "ModelName": "BMXP342020",
                "MajorMinorRevision": self.firmware,
                "SerialNumber": self.serial,
                "DeviceName": f"M340-{self.serial[-5:]}"
            }
    
    def get_registers(self) -> Dict:
        if self.profile_type == "siemens":
            return {
                'hr': [0] * 1000,
                'ir': [random.randint(0, 100) for _ in range(1000)],
                'co': [0] * 1000,
                'di': [random.randint(0, 1) for _ in range(1000)]
            }
        else:
            return {
                'hr': [0] * 2000,
                'ir': [random.randint(0, 255) for _ in range(2000)],
                'co': [0] * 2000,
                'di': [random.randint(0, 1) for _ in range(2000)]
            }

# Modbus honeypot with device emulation
class ModbusHoneypot:
    def __init__(self, device_profile: str = "siemens"):
        self.device = DeviceProfile(device_profile)
        logger.info(f"Initialized {device_profile.upper()} device profile - Serial: {self.device.serial}, Firmware: {self.device.firmware}")
        
    def get_device_info_string(self) -> str:
        info = self.device.device_info
        return f"{info['VendorName']} {info['ProductName']} {info['ModelName']} Serial:{info['SerialNumber']} FW:{info['MajorMinorRevision']}"

# Log Modbus TCP client connections
class ConnectionLogger:
    def __init__(self):
        self.active_connections = set()
        
    def log_connection(self, client_ip: str, action: str):
        logger.info(f"{client_ip} | {action}")
        
    def connection_made(self, transport):
        if hasattr(transport, 'get_extra_info'):
            peer = transport.get_extra_info('peername')
            if peer:
                client_ip = peer[0]
                self.active_connections.add(client_ip)
                self.log_connection(client_ip, "Connection established")
                
    def connection_lost(self, transport, exc):
        if hasattr(transport, 'get_extra_info'):
            peer = transport.get_extra_info('peername')
            if peer:
                client_ip = peer[0]
                self.active_connections.discard(client_ip)
                if exc:
                    self.log_connection(client_ip, "Connection failed")
                else:
                    self.log_connection(client_ip, "Connection closed")

connection_logger = ConnectionLogger()

# Async Modbus TCP protocol handler
class ModbusTCPServer:
    def __init__(self, honeypot: ModbusHoneypot):
        self.honeypot = honeypot
        
    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        client_ip = addr[0] if addr else "unknown"
        
        connection_logger.log_connection(client_ip, "Connection established")
        
        try:
            while True:
                data = await reader.read(1024)
                if not data:
                    break
                    
                if len(data) >= 8:
                    function_code = data[7] if len(data) > 7 else 0
                    
                    function_names = {
                        1: "Read Coils",
                        2: "Read Discrete Inputs", 
                        3: "Read Holding Registers",
                        4: "Read Input Registers",
                        5: "Write Single Coil",
                        6: "Write Single Register",
                        15: "Write Multiple Coils",
                        16: "Write Multiple Registers"
                    }
                    
                    function_name = function_names.get(function_code, f"Function {function_code}")
                    
                    if function_code in [1, 2, 3, 4]:
                        connection_logger.log_connection(client_ip, f"Read request - {function_name}")
                    elif function_code in [5, 6, 15, 16]:
                        connection_logger.log_connection(client_ip, f"Write attempt - {function_name}")
                        connection_logger.log_connection(client_ip, f"Write successful - {function_name}")
                    else:
                        connection_logger.log_connection(client_ip, f"Unknown request - Function {function_code}")
                
                response = data[:6] + bytes([0x02, 0x83, 0x02])
                writer.write(response)
                await writer.drain()
                
        except Exception as e:
            connection_logger.log_connection(client_ip, f"Connection error: {str(e)}")
        finally:
            connection_logger.log_connection(client_ip, "Connection closed")
            writer.close()
            await writer.wait_closed()

# Start the Modbus honeypot server
async def run_server(honeypot: ModbusHoneypot):
    server_instance = ModbusTCPServer(honeypot)
    
    server = await asyncio.start_server(
        server_instance.handle_client,
        '0.0.0.0',
        502
    )
    
    logger.info(f"Modbus honeypot server started on port 502")
    logger.info(f"Device type: {honeypot.device.profile_type.upper()}")
    logger.info(f"Serial: {honeypot.device.serial}")
    logger.info(f"Firmware: {honeypot.device.firmware}")
    
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    import sys
    
    device_profile = sys.argv[1] if len(sys.argv) > 1 else "siemens"
    if device_profile not in ["siemens", "schneider"]:
        device_profile = "siemens"
    
    honeypot = ModbusHoneypot(device_profile)
    
    try:
        asyncio.run(run_server(honeypot))
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")

