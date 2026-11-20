"""Top-bar icon for GNOME (via the AppIndicator / KStatusNotifierItem extension) and KDE.

Implements org.kde.StatusNotifierItem and com.canonical.dbusmenu directly over D-Bus with Gio, so it needs
no extra libraries and works next to GTK 4. GNOME Shell draws the menu itself, so it looks native.

Menu items are plain dicts:
  {"label": str, "enabled": bool, "visible": bool, "toggle": None|"checkmark", "state": bool,
   "icon": str, "action": callable, "separator": bool}
"""
import os

from gi.repository import Gio, GLib

SNI_XML = """
<node>
 <interface name="org.kde.StatusNotifierItem">
  <property name="Category" type="s" access="read"/>
  <property name="Id" type="s" access="read"/>
  <property name="Title" type="s" access="read"/>
  <property name="Status" type="s" access="read"/>
  <property name="IconName" type="s" access="read"/>
  <property name="IconThemePath" type="s" access="read"/>
  <property name="AttentionIconName" type="s" access="read"/>
  <property name="ToolTip" type="(sa(iiay)ss)" access="read"/>
  <property name="ItemIsMenu" type="b" access="read"/>
  <property name="Menu" type="o" access="read"/>
  <property name="XAyatanaLabel" type="s" access="read"/>
  <property name="XAyatanaLabelGuide" type="s" access="read"/>
  <method name="Activate"><arg type="i" direction="in"/><arg type="i" direction="in"/></method>
  <method name="SecondaryActivate"><arg type="i" direction="in"/><arg type="i" direction="in"/></method>
  <method name="ContextMenu"><arg type="i" direction="in"/><arg type="i" direction="in"/></method>
  <method name="Scroll"><arg type="i" direction="in"/><arg type="s" direction="in"/></method>
  <signal name="NewIcon"/>
  <signal name="NewAttentionIcon"/>
  <signal name="NewTitle"/>
  <signal name="NewToolTip"/>
  <signal name="NewStatus"><arg type="s"/></signal>
  <signal name="XAyatanaNewLabel"><arg type="s"/><arg type="s"/></signal>
 </interface>
</node>"""

MENU_XML = """
<node>
 <interface name="com.canonical.dbusmenu">
  <property name="Version" type="u" access="read"/>
  <property name="TextDirection" type="s" access="read"/>
  <property name="Status" type="s" access="read"/>
  <property name="IconThemePath" type="as" access="read"/>
  <method name="GetLayout">
   <arg type="i" direction="in"/><arg type="i" direction="in"/><arg type="as" direction="in"/>
   <arg type="u" direction="out"/><arg type="(ia{sv}av)" direction="out"/>
  </method>
  <method name="GetGroupProperties">
   <arg type="ai" direction="in"/><arg type="as" direction="in"/><arg type="a(ia{sv})" direction="out"/>
  </method>
  <method name="GetProperty">
   <arg type="i" direction="in"/><arg type="s" direction="in"/><arg type="v" direction="out"/>
  </method>
  <method name="Event">
   <arg type="i" direction="in"/><arg type="s" direction="in"/><arg type="v" direction="in"/><arg type="u" direction="in"/>
  </method>
  <method name="EventGroup">
   <arg type="a(isvu)" direction="in"/><arg type="ai" direction="out"/>
  </method>
  <method name="AboutToShow"><arg type="i" direction="in"/><arg type="b" direction="out"/></method>
  <method name="AboutToShowGroup">
   <arg type="ai" direction="in"/><arg type="ai" direction="out"/><arg type="ai" direction="out"/>
  </method>
  <signal name="ItemsPropertiesUpdated"><arg type="a(ia{sv})"/><arg type="a(ias)"/></signal>
  <signal name="LayoutUpdated"><arg type="u"/><arg type="i"/></signal>
  <signal name="ItemActivationRequested"><arg type="i"/><arg type="u"/></signal>
 </interface>
</node>"""

ITEM_PATH = "/StatusNotifierItem"
MENU_PATH = "/MenuBar"


class Tray:
    def __init__(self, app_id, title, icon_dir, on_activate=None):
        self.app_id, self.title = app_id, title
        self.icon_dir = icon_dir
        self.on_activate = on_activate
        self.icon, self.label, self.tooltip, self.status = "gitwarden-ok-symbolic", "", title, "Active"
        self.items = []          # list of dicts, ids are index+1 (0 is the root)
        self.revision = 1
        self.bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        self.bus_name = f"org.kde.StatusNotifierItem-{os.getpid()}-1"
        sni = Gio.DBusNodeInfo.new_for_xml(SNI_XML).interfaces[0]
        menu = Gio.DBusNodeInfo.new_for_xml(MENU_XML).interfaces[0]
        self.bus.register_object(ITEM_PATH, sni, self._sni_call, self._sni_get, None)
        self.bus.register_object(MENU_PATH, menu, self._menu_call, self._menu_get, None)
        Gio.bus_own_name_on_connection(self.bus, self.bus_name, Gio.BusNameOwnerFlags.NONE, None, None)
        self.registered = False
        self.on_host_change = None  # called with True/False when the top-bar host appears or goes away
        # Registers now if the host is there, and again whenever it (re)appears: e.g. the AppIndicator
        # extension being turned back on, or GNOME Shell restarting.
        self._watch = Gio.bus_watch_name_on_connection(
            self.bus, "org.kde.StatusNotifierWatcher", Gio.BusNameWatcherFlags.NONE, self._register, self._vanished)

    @property
    def host(self):
        return self.registered

    def _vanished(self, *_):
        if self.registered:
            self.registered = False
            if self.on_host_change:
                self.on_host_change(False)

    # ---------------------------------------------------------------- registration
    def _register(self, *_):
        def done(bus, res):
            try:
                bus.call_finish(res)
                self.registered = True
                if self.on_host_change:
                    self.on_host_change(True)
            except GLib.Error as e:
                print("GitWarden: could not add the top-bar icon:", e.message)
        self.bus.call("org.kde.StatusNotifierWatcher", "/StatusNotifierWatcher", "org.kde.StatusNotifierWatcher",
                      "RegisterStatusNotifierItem", GLib.Variant("(s)", (self.bus_name,)), None,
                      Gio.DBusCallFlags.NONE, -1, None, done)

    @staticmethod
    def available():
        bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        try:
            r = bus.call_sync("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "NameHasOwner",
                              GLib.Variant("(s)", ("org.kde.StatusNotifierWatcher",)), None, Gio.DBusCallFlags.NONE, 2000, None)
            return r.unpack()[0]
        except GLib.Error:
            return False

    def _emit(self, path, iface, name, params=None):
        self.bus.emit_signal(None, path, iface, name, params)

    # ---------------------------------------------------------------- public API
    def set_state(self, icon=None, label=None, tooltip=None, attention=None):
        if icon is not None and icon != self.icon:
            self.icon = icon
            self._emit(ITEM_PATH, "org.kde.StatusNotifierItem", "NewIcon")
        if label is not None and label != self.label:
            self.label = label
            self._emit(ITEM_PATH, "org.kde.StatusNotifierItem", "XAyatanaNewLabel", GLib.Variant("(ss)", (label, "")))
        if tooltip is not None and tooltip != self.tooltip:
            self.tooltip = tooltip
            self._emit(ITEM_PATH, "org.kde.StatusNotifierItem", "NewToolTip")
        if attention is not None:
            status = "NeedsAttention" if attention else "Active"
            if status != self.status:
                self.status = status
                self._emit(ITEM_PATH, "org.kde.StatusNotifierItem", "NewStatus", GLib.Variant("(s)", (status,)))

    def set_menu(self, items):
        self.items = items
        self.revision += 1
        self._emit(MENU_PATH, "com.canonical.dbusmenu", "LayoutUpdated", GLib.Variant("(ui)", (self.revision, 0)))

    # ---------------------------------------------------------------- StatusNotifierItem
    def _sni_get(self, conn, sender, path, iface, prop):
        v = {
            "Category": ("s", "ApplicationStatus"), "Id": ("s", self.app_id), "Title": ("s", self.title),
            "Status": ("s", self.status), "IconName": ("s", self.icon), "IconThemePath": ("s", self.icon_dir),
            "AttentionIconName": ("s", self.icon), "ItemIsMenu": ("b", True), "Menu": ("o", MENU_PATH),
            "ToolTip": ("(sa(iiay)ss)", ("", [], self.title, self.tooltip)),
            "XAyatanaLabel": ("s", self.label), "XAyatanaLabelGuide": ("s", ""),
        }.get(prop)
        return GLib.Variant(*v) if v else None

    def _sni_call(self, conn, sender, path, iface, method, params, inv):
        if method in ("Activate", "SecondaryActivate") and self.on_activate:
            GLib.idle_add(self.on_activate)
        inv.return_value(None)

    # ---------------------------------------------------------------- dbusmenu
    def _props(self, i):
        if i == 0:
            return {"children-display": GLib.Variant("s", "submenu")}
        it = self.items[i - 1]
        if it.get("separator"):
            return {"type": GLib.Variant("s", "separator")}
        p = {"label": GLib.Variant("s", it.get("label", "").replace("_", "__")),
             "enabled": GLib.Variant("b", it.get("enabled", True)),
             "visible": GLib.Variant("b", it.get("visible", True))}
        if it.get("icon"):
            p["icon-name"] = GLib.Variant("s", it["icon"])
        if it.get("toggle"):
            p["toggle-type"] = GLib.Variant("s", it["toggle"])
            p["toggle-state"] = GLib.Variant("i", 1 if it.get("state") else 0)
        return p

    def _node(self, i, depth):
        children = []
        if i == 0 and depth != 0:
            children = [GLib.Variant("(ia{sv}av)", (n, self._props(n), [])) for n in range(1, len(self.items) + 1)]
        return (i, self._props(i), children)

    def _menu_get(self, conn, sender, path, iface, prop):
        return {"Version": GLib.Variant("u", 3), "TextDirection": GLib.Variant("s", "ltr"),
                "Status": GLib.Variant("s", "normal"), "IconThemePath": GLib.Variant("as", [self.icon_dir])}.get(prop)

    def _valid(self, i):
        return 0 <= i <= len(self.items)

    def _menu_call(self, conn, sender, path, iface, method, params, inv):
        a = params.unpack()
        if method == "GetLayout":
            parent, depth = a[0], a[1]
            parent = parent if self._valid(parent) else 0
            inv.return_value(GLib.Variant("(u(ia{sv}av))", (self.revision, self._node(parent, depth))))
        elif method == "GetGroupProperties":
            ids = a[0] or range(0, len(self.items) + 1)
            inv.return_value(GLib.Variant("(a(ia{sv}))", ([(i, self._props(i)) for i in ids if self._valid(i)],)))
        elif method == "GetProperty":
            v = self._props(a[0]).get(a[1]) if self._valid(a[0]) else None
            if v is None:
                inv.return_dbus_error("com.canonical.dbusmenu.Error", "no such property")
            else:
                inv.return_value(GLib.Variant("(v)", (v,)))
        elif method == "Event":
            self._event(a[0], a[1])
            inv.return_value(None)
        elif method == "EventGroup":
            for i, ev, _, _ in a[0]:
                self._event(i, ev)
            inv.return_value(GLib.Variant("(ai)", ([],)))
        elif method == "AboutToShow":
            inv.return_value(GLib.Variant("(b)", (False,)))
        elif method == "AboutToShowGroup":
            inv.return_value(GLib.Variant("(aiai)", ([], [])))
        else:
            inv.return_dbus_error("org.freedesktop.DBus.Error.UnknownMethod", method)

    def _event(self, i, ev):
        if ev == "clicked" and 1 <= i <= len(self.items):
            act = self.items[i - 1].get("action")
            if act:
                GLib.idle_add(lambda: (act(), False)[1])
