# HexRDP — Professional Android RDP Client

A modern, feature-rich Remote Desktop Protocol (RDP) client for Android with a stunning space-themed UI, built to work on the weakest network connections.

## Features

- **Pure Kotlin RDP** — No NDK required, builds entirely via GitHub Actions
- **Multi-Session** — Add and manage multiple RDP connections
- **Adaptive Quality** — Auto-adjusts resolution/compression based on network speed
- **Touchpad Mode** — Use the screen like a laptop trackpad
- **Extra Keys Bar** — F1-F12, Ctrl, Alt, Win, Del, and more above the keyboard
- **Mouse Cursor** — Visible cursor on screen
- **NLA Authentication** — Full NTLM/CredSSP support
- **Arabic & English** — Full RTL support
- **Space Theme** — Professional dark/light themes with nebula effects
- **Dark/Light Mode** — Auto-detects system preference
- **All Screen Sizes** — Adaptive layout for phones and tablets

## Build via GitHub Actions (No Android Studio Needed)

### 1. Fork or upload this project to GitHub

```bash
git init
git add .
git commit -m "Initial commit - HexRDP"
git remote add origin https://github.com/YOUR_USERNAME/HexRDP.git
git push -u origin main
```

### 2. GitHub Actions builds automatically

Every push to `main` triggers a build. Go to:
```
GitHub Repo → Actions → Build HexRDP APK → Latest run → Artifacts
```
Download `HexRDP-debug-*.apk` and install on your device.

### 3. Release Build with Signing (Optional)

To create a signed release APK, add these GitHub Secrets:
```
Settings → Secrets and variables → Actions → New repository secret
```

| Secret | Value |
|--------|-------|
| `KEYSTORE_BASE64` | Base64-encoded `.jks` keystore file |
| `KEY_ALIAS` | Your key alias |
| `KEYSTORE_PASSWORD` | Keystore password |
| `KEY_PASSWORD` | Key password |

Then create a tag to trigger release:
```bash
git tag v1.0.0
git push origin v1.0.0
```

## Generate a Keystore (for signing)

```bash
keytool -genkey -v -keystore hexrdp.jks -alias hexrdp -keyalg RSA -keysize 2048 -validity 10000
# Then encode to base64:
base64 -w 0 hexrdp.jks
# Paste the output as KEYSTORE_BASE64 secret
```

## Project Structure

```
HexRDP/
├── .github/workflows/build.yml     # GitHub Actions CI/CD
├── app/
│   ├── src/main/
│   │   ├── java/com/gotohex/rdp/
│   │   │   ├── data/
│   │   │   │   ├── db/             # Room database
│   │   │   │   ├── model/          # Data models
│   │   │   │   └── repository/     # Repositories + DataStore
│   │   │   ├── di/                 # Hilt DI modules
│   │   │   ├── rdp/
│   │   │   │   ├── codec/          # Bitmap decoders
│   │   │   │   └── protocol/       # RDP protocol + NTLM
│   │   │   └── ui/
│   │   │       ├── components/     # Reusable UI components
│   │   │       ├── screens/        # Home, Session, Settings
│   │   │       ├── theme/          # Colors, Typography, Theme
│   │   │       └── MainActivity.kt
│   │   └── res/                    # Resources (strings, drawables, xml)
│   └── build.gradle.kts
├── gradle/libs.versions.toml       # Version catalog
└── settings.gradle.kts
```

## Technical Stack

| Layer | Technology |
|-------|-----------|
| UI | Jetpack Compose + Material3 |
| Architecture | MVVM + Hilt DI |
| Database | Room |
| Preferences | DataStore |
| Async | Kotlin Coroutines + Flow |
| RDP Protocol | Pure Kotlin (custom implementation) |
| Encryption | BouncyCastle (TLS + NTLM/NLA) |
| Images | Coil |
| Animation | Compose animations + Lottie |

## RDP Protocol Details

The RDP client implements:
- **X.224 / MCS / T.125** — Connection negotiation
- **TLS Upgrade** — Automatic TLS wrapping after X.224
- **NLA (CredSSP)** — NTLM v2 authentication
- **Fast-Path Input** — Low-latency mouse/keyboard events
- **Bitmap Updates** — Raw, RLE, and JPEG decompression
- **Adaptive Compression** — Automatic quality based on bandwidth

## Network Performance Modes

| Mode | Bandwidth | Color Depth | Compression |
|------|-----------|-------------|-------------|
| Auto | Detected | Dynamic | Adaptive |
| LAN | >2 Mbps | 32-bit | Raw/Light |
| WiFi | >500 Kbps | 24-bit | RLE |
| Medium | >100 Kbps | 16-bit | RLE |
| Low | <100 Kbps | 8-bit | JPEG 40% |

## Developer

**GoToHEX** — [t.me/GoToHEX](https://t.me/GoToHEX)

---

*Built with Kotlin + Jetpack Compose. Space-themed UI designed for 2026.*
