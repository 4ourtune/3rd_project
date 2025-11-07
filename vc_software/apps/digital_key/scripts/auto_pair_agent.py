#!/usr/bin/env python3
"""BLE pairing agent that auto-accepts numeric comparison."""
from __future__ import annotations

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib


AGENT_PATH = "/com/example/AutoPairAgent"


class AutoPairAgent(dbus.service.Object):
    """Minimal D-Bus agent that always confirms pairing requests."""

    def __init__(self, bus: dbus.bus.BusConnection):
        super().__init__(bus, AGENT_PATH)

    @dbus.service.method("org.bluez.Agent1", in_signature="ou", out_signature="")
    def DisplayYesNo(self, device: str, passkey: dbus.UInt32) -> None:  # pylint: disable=invalid-name
        print(f"[auto-pair] DisplayYesNo for {device} passkey={passkey} -> auto-yes")

    @dbus.service.method("org.bluez.Agent1", in_signature="ou", out_signature="")
    def RequestConfirmation(  # pylint: disable=invalid-name
        self,
        device: str,
        passkey: dbus.UInt32,
    ) -> None:
        print(f"[auto-pair] RequestConfirmation for {device} passkey={passkey} -> auto-yes")

    @dbus.service.method("org.bluez.Agent1", in_signature="", out_signature="")
    def Cancel(self) -> None:
        print("[auto-pair] pairing cancelled by remote")

    @dbus.service.method("org.bluez.Agent1", in_signature="", out_signature="")
    def Release(self) -> None:
        print("[auto-pair] agent released")


def main() -> None:
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    manager = dbus.Interface(
        bus.get_object("org.bluez", "/org/bluez"),
        "org.bluez.AgentManager1",
    )

    agent = AutoPairAgent(bus)
    manager.RegisterAgent(AGENT_PATH, "DisplayYesNo")
    manager.RequestDefaultAgent(AGENT_PATH)
    print("[auto-pair] agent registered as default (DisplayYesNo)")

    loop = GLib.MainLoop()
    loop.run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
