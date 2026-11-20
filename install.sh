#!/bin/sh
# Installs GitWarden for the current user only (no sudo): a `gitwarden` command, an app-menu entry, and
# (optional) start at login. Run from this folder: ./install.sh   Remove with: ./install.sh --uninstall
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
APP_ID=io.github.itspsychocoder.GitWarden
BIN="$HOME/.local/bin/gitwarden"
APPS="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
ICONS="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/scalable/apps"
AUTO="${XDG_CONFIG_HOME:-$HOME/.config}/autostart/$APP_ID.desktop"

if [ "${1:-}" = "--uninstall" ]; then
  rm -f "$BIN" "$APPS/$APP_ID.desktop" "$ICONS/$APP_ID.svg" "$AUTO"
  echo "GitWarden removed. Your settings stay in ~/.config/gitwarden and ~/.local/state/gitwarden."
  exit 0
fi

missing=""
python3 -c 'import gi; gi.require_version("Gtk","4.0"); gi.require_version("Adw","1")' 2>/dev/null || missing="python3-gi gir1.2-gtk-4.0 gir1.2-adw-1"
command -v git >/dev/null || missing="$missing git"
if [ -n "$missing" ]; then
  echo "Install these first:  sudo apt install $missing"; exit 1
fi

mkdir -p "$(dirname "$BIN")" "$APPS" "$ICONS"
ln -sf "$HERE/bin/gitwarden" "$BIN"
cp "$HERE/gitwarden/icons/hicolor/scalable/apps/$APP_ID.svg" "$ICONS/"
touch "$(dirname "$(dirname "$ICONS")")"  # tell GNOME the icon folder changed, so the dock picks up the new icon
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q "$APPS" 2>/dev/null || true
cat > "$APPS/$APP_ID.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=GitWarden
Comment=Watches your GitHub repos for the git malware worm
Exec="$HERE/bin/gitwarden"
Icon=$APP_ID
Terminal=false
Categories=Development;Security;
StartupNotify=true
DESKTOP
python3 -I -c "import sys; sys.path.insert(0, '$HERE'); from gitwarden import autostart; autostart.set_enabled(True)"
echo "Installed. Open GitWarden from the app menu, or run: gitwarden"
echo "It will also start in the top bar when you sign in (turn off in Settings)."
gnome-extensions list --enabled 2>/dev/null | grep -qiE "appindicator" || \
  echo "Note: enable the 'AppIndicator' GNOME extension to see the top-bar icon."
