# Fonts (issue #7)

This folder currently contains **minimal placeholder `.ttf` files** (each only
defines a glyph for "A" and space) so the project builds and runs correctly
out of the box. The app already references these files by name from
`ui/theme/Theme.kt` and the `font_*.xml` font-family resources.

To get the real space-themed fonts, download the following **OFL-licensed**
families from Google Fonts and overwrite the placeholder files **using the
exact same filenames** — no code changes are needed:

| File                          | Replace with                                  |
|--------------------------------|-----------------------------------------------|
| `orbitron_medium.ttf`           | Orbitron — Medium (500)                       |
| `orbitron_semibold.ttf`         | Orbitron — SemiBold (600)                     |
| `orbitron_bold.ttf`             | Orbitron — Bold (700)                         |
| `rajdhani_regular.ttf`          | Rajdhani — Regular (400)                      |
| `rajdhani_medium.ttf`           | Rajdhani — Medium (500)                       |
| `rajdhani_semibold.ttf`         | Rajdhani — SemiBold (600)                     |
| `share_tech_mono.ttf`           | Share Tech Mono — Regular (400)               |
| `tajawal_regular.ttf`           | Tajawal — Regular (400)                       |
| `tajawal_medium.ttf`            | Tajawal — Medium (500)                        |
| `tajawal_bold.ttf`              | Tajawal — Bold (700)                          |

Sources:
- https://fonts.google.com/specimen/Orbitron
- https://fonts.google.com/specimen/Rajdhani
- https://fonts.google.com/specimen/Share+Tech+Mono
- https://fonts.google.com/specimen/Tajawal

## Usage in the app

- **Orbitron** → all headings/titles (`displayLarge` … `titleLarge`) for
  English/Latin text — gives the "space / sci-fi HUD" look.
- **Rajdhani** → body text (`bodyLarge`, `bodyMedium`, `bodySmall`,
  `titleMedium`, `titleSmall`, `labelLarge`).
- **Share Tech Mono** → small console-style labels (`labelMedium`,
  `labelSmall`) — latency readouts, key labels, etc.
- **Tajawal** → automatically used as the fallback face for Arabic text in
  every style above, so Arabic content gets a matching modern look even
  while the Latin font is Orbitron/Rajdhani/Share Tech Mono.

If any of these files are ever missing or fail to parse, Android/Compose
falls back to the next font in the `FontFamily` list (eventually the system
default) — the app will never crash because of a missing/invalid font file.
