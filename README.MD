# C++ HTTPS Server and Client — 🧑‍🏭

## 📌 Simple Overview

**Native C++ HTTPS server and client** (communicating over an **SSL/TLS-encrypted channel** using **OpenSSL**). The server responds with a **basic** message over HTTPS, while the client initiates an HTTPS GET request and prints the response.

---

### 💡 How it works (OpenSSL)

1. The **server** loads a TLS certificate and private key.
2. The **client** connects and initiates an SSL/TLS handshake.
3. Both negotiate a cipher suite and exchange cryptographic keys.
4. All communication after this is encrypted with symmetric encryption.

In this project:

* **OpenSSL** provides the **SSL\_CTX**, **SSL** objects and handles the handshake and encryption logic.
* **Sockets** (Winsock on Windows or BSD sockets on Linux) handle low-level data transport.

---

## 📦 Libraries Used

### ✅ OpenSSL (libssl & libcrypto)

* Open-source library for SSL/TLS.
* Used to create secure connections in both client and server.

### ✅ Native Socket APIs

* **Windows**: Winsock2 (`winsock2.h`, `ws2tcpip.h`)
* **Linux**: BSD sockets (`netinet/in.h`, `sys/socket.h`, `arpa/inet.h`)

No heavy frameworks like Boost are required.

---

## 🧪 Server Summary

* Listens on port `4433` on `localhost`
* Uses OpenSSL to perform TLS handshake
* Sends basic HTTP response `Hello, World!`

## 🧪 Client Summary

* Connects to `localhost:4433`
* Performs TLS handshake
* Sends simple GET request
* Prints response to stdout

---

## 🛠️ Setup Instructions

### 📁 File Structure

```
/project-root/
├── cert.pem          ← TLS Certificate
├── key.pem           ← TLS Private Key
├── https_server.cpp  ← Cross-platform HTTPS server
├── https_client.cpp  ← Cross-platform HTTPS client
```

---

## 🛡️ Step 1: Generate a Self-Signed SSL Certificate

Run this in **Linux/macOS** terminal or **PowerShell/CMD** on Windows (if OpenSSL is in PATH):

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

* Common Name (CN): `localhost`
* Output:

  * `cert.pem`: Self-signed certificate
  * `key.pem`: RSA private key

---

## 🪟 Windows Setup Instructions

### 1. Install [MinGW-w64](https://www.mingw-w64.org/)

* Make sure `g++` is in your PATH

### 2. Install OpenSSL

#### Option A: Prebuilt Binaries

* Go to [https://slproweb.com/products/Win32OpenSSL.html](https://slproweb.com/products/Win32OpenSSL.html)
* Download **Full Win64 OpenSSL**
* Check the box to install **headers**

#### Option B: Using vcpkg (Recommended)

```bash
git clone https://github.com/microsoft/vcpkg
cd vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg install openssl:x64-windows
```

---

## 🐧 Linux Setup Instructions

```bash
sudo apt update
sudo apt install build-essential libssl-dev
```

---

## 🧱 Compilation Instructions

### 🔨 Windows (MinGW + OpenSSL via vcpkg)

```bash
g++ https_server.cpp -o server ^
  -I"path\to\vcpkg\installed\x64-windows\include" ^
  -L"path\to\vcpkg\installed\x64-windows\lib" ^
  -lssl -lcrypto -lws2_32 -static-libgcc -static-libstdc++
```

```bash
g++ https_client.cpp -o client ^
  -I"path\to\vcpkg\installed\x64-windows\include" ^
  -L"path\to\vcpkg\installed\x64-windows\lib" ^
  -lssl -lcrypto -lws2_32 -static-libgcc -static-libstdc++
```

Replace `path\to\...` with the actual location of your vcpkg OpenSSL install.

---

### 🔨 Linux

```bash
g++ https_server.cpp -o server -lssl -lcrypto
g++ https_client.cpp -o client -lssl -lcrypto
```

---

## 🚀 Running the Programs

1. **Start the Server**:

   ```bash
   ./server
   ```

   Output:

   ```
   Server running on https://localhost:4433
   ```

2. **Run the Client**:

   ```bash
   ./client
   ```

   Output:

   ```
    PS C:\Users\Frost\Desktop\Scratch> ./client
    Received:
    HTTP/1.1 200 OK
    Content-Type: text/plain

    OMG I'm gonna cry-- it works. I'm aliveeeee. Hello, World!
   ```

---

## 🔐 Security Notes

* The server uses a **self-signed certificate**, so browsers and strict TLS clients will reject it unless trusted.
* For production, use certificates issued by trusted Certificate Authorities (like Let's Encrypt).
* This is a **single-threaded demo** and not suitable for production load without multithreading or event-loop design.
