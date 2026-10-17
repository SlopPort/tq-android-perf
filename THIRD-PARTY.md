# Third-party components

- **Frida** (`frida-inject`, CModule): https://frida.re, licensed under the wxWindows Library Licence 3.1.
  The installable zip bundles the unmodified `frida-inject` binary for android-arm64 from the official release
  (`module/build.py` downloads it).
- **Magisk module installer** (`module/META-INF/com/google/android/update-binary`): the standard module installer
  script from the Magisk documentation.
- **Titan Quest** is a trademark of THQ Nordic. This project is an unofficial, non-commercial fan project. It is not
  affiliated with or endorsed by THQ Nordic or HandyGames. It contains no game files, game code or assets: the module
  patches the user's own installed copy in memory, and the tools that read `libtq.so` read the user's own copy.
