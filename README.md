 (The Technical Breakdown)
The framework shifts the system's defensive perimeter across time using a coordinated four-step process between the client and the server:
### 1. Segmentation of Time (Epochs)
The system divides continuous time into distinct blocks called **Epochs** based on your configured rotation_interval (e.g., every 10 seconds).

### 2. Cryptographic Mutation Generation
Inside the **Control Plane**, the current Epoch number is cryptographically hashed against a hidden seed key using **HMAC-SHA256**. The resulting hash is deterministically mapped to an integer between 1 and 26. This integer becomes the active alphanumeric shift key for that specific time window. Because it uses HMAC, an attacker cannot guess the next shift key even if they know the current time.
### 3. Dynamic Payload Obfuscation
 * **The Client Side:** Before sending an API request or command (like get_status), the legitimate user's application calculates the current epoch, generates the matching shift key, and dynamically obfuscates the payload using an alpha-shifting cipher.
 * **The Network Shift:** If the active shift key is 4, the string get_status morphs on the wire into kix_wxexyw.
### 4. Verification & Automated Enforcement
When the network packet hits the **Data Plane**, the server:
 1. **Checks the Blocklist:** Drops the connection immediately if the inbound IP address is already flagged.
 2. **Synchronizes the Time Window:** Validates the incoming epoch attached to the packet.
 3. **Applies the Reverse Cipher:** Shifts the characters backward using the mathematically derived key to read the true underlying instruction.
 4. **Evaluates Intent:** If the decrypted string matches a valid command in the system manifest, it executes. If the payload is unreadable (a hacker sending standard text or an expired signature), the system records a security strike against that IP.
### 🛟 The Mobile Latency Cushion
In real-world mobile networks (4G/5G/Wi-Fi transitions), packets can lag. If a request arrives a split second after a new epoch begins, traditional time-matching systems break. This framework includes a **one-epoch grace window**. If a packet arrives matching the *immediate past epoch*, the server dynamically spins up historical context to decode and accept it safely, preventing false positives for legitimate users.
## 🛠️ Requirements to Use It
One of the best selling points of this public core framework is that it is incredibly lightweight and has **zero external dependencies**.
### 1. Software Requirements
 * **Python 3.8 or higher:** The codebase leverages modern Python features, including advanced type-hinting, abstract base classes (abc), and asynchronous subprocess management via asyncio.
### 2. Dependencies (Standard Library Only)
You do not need to run pip install for any third-party packages. The system runs entirely on native, highly optimized Python standard libraries:
 * asyncio - For high-concurrency, non-blocking asynchronous event loops.
 * hmac & hashlib - For enterprise-grade cryptographic verification.
 * time - For UNIX epoch tracking.
 * logging - For structured, production-ready security event audit trails.
### 3. Operating System Compatibility
 * **This Core Framework:** 100% Cross-platform. Because this public version utilizes an application-layer LocalBanManager, it runs seamlessly on **Windows, macOS, and Linux**.
 * *Note on Enterprise Extensions:* The private commercial upgrades (which hook directly into iptables or nftables) require a Linux kernel environment with root/sudo administrative privileges.
