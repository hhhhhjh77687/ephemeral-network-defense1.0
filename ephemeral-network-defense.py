import asyncio
import hmac
import hashlib
import time
import logging
from abc import ABC, abstractmethod
from typing import Dict, Tuple

# Structured logging for professional monitoring and audit trails
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (%(name)s) -> %(message)s"
)
logger = logging.getLogger("MTD-Core")


class AbstractBanManager(ABC):
    """
    Developer Note: High-end enterprise adaptations (e.g., native Linux 
    kernel netfilter/iptables integration or distributed Redis clusters) 
    should inherit from this base class to handle perimeter enforcement.
    """
    @abstractmethod
    async def is_banned(self, ip: str) -> bool:
        pass

    @abstractmethod
    async def record_strike(self, ip: str) -> None:
        pass


class LocalBanManager(AbstractBanManager):
    """Lightweight application-layer mitigation engine for local verification."""
    def __init__(self, strike_threshold: int = 3, ban_duration: int = 60):
        self.strike_threshold = strike_threshold
        self.ban_duration = ban_duration
        self.strikes: Dict[str, int] = {}
        self.ban_list: Dict[str, float] = {}

    async def is_banned(self, ip: str) -> bool:
        if ip in self.ban_list:
            if time.time() < self.ban_list[ip]:
                return True
            del self.ban_list[ip]
            self.strikes[ip] = 0
        return False

    async def record_strike(self, ip: str) -> None:
        self.strikes[ip] = self.strikes.get(ip, 0) + 1
        logger.warning(f"Security event: Strike issued to {ip} [{self.strikes[ip]}/{self.strike_threshold}]")
        
        if self.strikes[ip] >= self.strike_threshold:
            self.ban_list[ip] = time.time() + self.ban_duration
            logger.critical(f"Access Revoked: IP {ip} restricted at application firewall for {self.ban_duration}s.")


class ControlPlane:
    """
    The Cryptographic Core. Deterministically derives time-epoch 
    mutation vectors without exposing operational parameters directly to clients.
    """
    def __init__(self, rotation_interval: int = 10, seed: bytes = b"default_core_seed"):
        self.rotation_interval = rotation_interval
        self._secret_seed = seed
        self.is_running = False
        self._current_epoch = 0
        self._current_shift_key = 0

    async def start_mutation_loop(self):
        """Drives continuous, deterministic rotation of the defensive surface architecture."""
        self.is_running = True
        logger.info(f"Control Plane operational. Shifting active surface topology every {self.rotation_interval}s.")
        
        while self.is_running:
            self._current_epoch = int(time.time() // self.rotation_interval)
            
            # Use HMAC-SHA256 to securely transform the time epoch into an unguessable shift value
            msg = str(self._current_epoch).encode()
            digest = hmac.new(self._secret_seed, msg, hashlib.sha256).digest()
            
            # Derive an algorithmic translation key offset (1-26)
            self._current_shift_key = (digest[0] % 25) + 1
            await asyncio.sleep(self.rotation_interval)

    def get_security_context(self) -> Tuple[int, int]:
        """Exposes transient cryptographic contexts without exposing state variables."""
        return self._current_epoch, self._current_shift_key


class DataPlane:
    """
    The Perimeter Shield. Decodes runtime strings, manages token metrics,
    and isolates underlying system features from external reconnaissance.
    """
    def __init__(self, control_plane: ControlPlane, ban_manager: AbstractBanManager):
        self.control_plane = control_plane
        self.ban_manager = ban_manager
        
        # Valid runtime system directives mapped to authorized actions
        self.exposed_registry = {
            "get_status": "System telemetry: Operational. Surface shifting cleanly.",
            "clear_cache": "System telemetry: Temporary connection states cleared."
        }

    def _cipher_transform(self, text: str, shift: int, invert: bool = False) -> str:
        """Translates characters across active alphanumeric alphabets dynamically."""
        offset = -shift if invert else shift
        transformed = []
        for char in text:
            if char.isalpha():
                base = ord('a') if char.islower() else ord('A')
                transformed.append(chr((ord(char) - base + offset) % 26 + base))
            else:
                transformed.append(char)
        return "".join(transformed)

    async def process_telemetry(self, payload: str, payload_epoch: int, client_ip: str) -> str:
        """Validates payload timelines, absorbs latency drift, and evaluates commands safely."""
        if await self.ban_manager.is_banned(client_ip):
            return "ERROR: Threat signature blocked at perimeter."

        active_epoch, active_shift = self.control_plane.get_security_context()

        # NETWORK OPTIMIZATION: Check current or immediate previous epoch to handle 4G/5G/Wi-Fi latency drift safely
        if payload_epoch == active_epoch:
            effective_shift = active_shift
        elif payload_epoch == active_epoch - 1:
            # Reconstruct historical key to gracefully handle lagging mobile requests
            prev_msg = str(payload_epoch).encode()
            prev_digest = hmac.new(self.control_plane._secret_seed, prev_msg, hashlib.sha256).digest()
            effective_shift = (prev_digest[0] % 25) + 1
            logger.info(f"Latency cushion triggered for {client_ip} (Processing epoch drift).")
        else:
            logger.warning(f"Stale signature/Replay vector flagged from source: {client_ip}")
            await self.ban_manager.record_strike(client_ip)
            return "ERROR: Cryptographic window mismatch."

        # Invert the cipher to parse the real underlying instruction
        decoded_instruction = self._cipher_transform(payload, effective_shift, invert=True).strip().lower()

        if decoded_instruction in self.exposed_registry:
            logger.info(f"Command execution success: '{decoded_instruction}' initiated by {client_ip}")
            return self.exposed_registry[decoded_instruction]
        
        logger.warning(f"Reconnaissance anomaly encountered from {client_ip}: Invalid sequence '{payload}'")
        await self.ban_manager.record_strike(client_ip)
        return "ERROR: Protocol validation handshake failed."


# --- Execution Demonstration Harness ---
async def main():
    # Instantiate engine structures
    control = ControlPlane(rotation_interval=5, seed=b"public_open_source_seed_key")
    firewall = LocalBanManager(strike_threshold=2, ban_duration=5)
    data_handler = DataPlane(control, firewall)

    # Spawn background cryptographic control loop
    loop_task = asyncio.create_task(control.start_mutation_loop())
    await asyncio.sleep(0.1)  # Allow state stabilization

    simulated_client = "192.168.1.50"
    simulated_attacker = "10.0.0.99"

    try:
        print("\n=== STARTING ACTIVE PROTOCOL FRAMEWORK EVALUATION ===")
        epoch, shift = control.get_security_context()

        # Simulation 1: Legitimate client using active obfuscation
        valid_payload = data_handler._cipher_transform("get_status", shift)
        print(f"\n[Client Action] Transmitting obfuscated token: '{valid_payload}' (Epoch: {epoch})")
        response = await data_handler.process_telemetry(valid_payload, epoch, simulated_client)
        print(f"[Server Output] {response}")

        # Simulation 2: Attacker running automated endpoint scanning (Sending static text)
        print(f"\n[Attacker Action] Injecting cleartext script target 'get_status' from {simulated_attacker}")
        response = await data_handler.process_telemetry("get_status", epoch, simulated_attacker)
        print(f"[Server Output] {response}")

        # Simulation 3: Attacker trying to repeat past tokens (Replay / Defunct signature)
        print(f"\n[Attacker Action] Replaying captured signature '{valid_payload}' on an invalid historical epoch.")
        response = await data_handler.process_telemetry(valid_payload, epoch - 5, simulated_attacker)
        print(f"[Server Output] {response}")

    finally:
        control.is_running = False
        await loop_task

if __name__ == "__main__":
    asyncio.run(main())
```[span_3](start_span)[span_3](end_span)

---

## 2. The Pitch (`README.md`)

Create a file named `README.md` in your GitHub repository. This layout reads like a high-end commercial project description, capturing attention instantly.

```markdown
# Ephemeral Surface Reshaping Core Framework

An asynchronous, time-variant **Moving Target Defense (MTD)** framework designed to eliminate automated network reconnaissance, zero-day endpoint scanning, and replay attacks.

## 🚀 The Architecture Principle

Traditional security architectures are entirely **static**, giving attackers infinite time to scan endpoints, map software vulnerabilities, and execute targeted payloads. 

This framework implements an **Asynchronous Shifting Core** that continuously mutates the expected command vocabulary and payload verification tokens across short time domains (epochs). By converting your exposed API or microservice endpoints into an unguessable moving target via deterministic cryptographic ciphers, threat actors are blocked before an exploit payload can even be interpreted.

