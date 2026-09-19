import hashlib
import logging

import gevent
import gevent.lock
import gevent.socket as socket
import util.RH_GPIO as RH_GPIO
from gevent.queue import Queue
from RHRace import RaceStatus, WinCondition
from VRxControl import VRxController

from .connections import BackpackConnection, ConnectionTypeEnum
from .msp import MSPPacket, MSPPacketType, MSPTypes
from .osd_layout import element, parse_comm_osd

logger = logging.getLogger(__name__)


class CancelError(BaseException): ...


class ELRSBackpack(VRxController):
    _connection: BackpackConnection | None = None

    def __init__(self, name, label, rhapi):
        super().__init__(name, label)
        self._rhapi = rhapi
        self._send_queue = Queue()
        self._recieve_queue = Queue(maxsize=100)
        self._queue_lock = gevent.lock.RLock()
        self._osd_layouts: dict[int, dict | None] = {}

    @property
    def _backpack_connected(self) -> bool:
        if self._connection is None:
            return False

        return self._connection.connected

    def register_handlers(self, args) -> None:
        """
        Registers handlers in the RotorHazard system
        """
        args["register_fn"](self)

    def start_race(self):
        """
        Start the race
        """
        if self._rhapi.db.option("_race_start") == "1":
            start_race_args = {"start_time_s": 10}
            if self._rhapi.race.status == RaceStatus.READY:
                self._rhapi.race.stage(start_race_args)

    def stop_race(self):
        """
        Stop the race
        """
        if self._rhapi.db.option("_race_stop") == "1":
            status = self._rhapi.race.status
            if status in (RaceStatus.STAGING, RaceStatus.RACING):
                if self._rhapi.db.option("_autosave_on_stop") == "1":
                    self._rhapi.race.save()
                else:
                    self._rhapi.race.stop()

    #
    # Connection handling
    #

    def start_recieve_loop(self, *_):
        """
        Start the msp packet processing loop
        """
        gevent.spawn(self.recieve_loop)
        logger.info("Backpack recieve greenlet started.")

    def start_connection(self, *_) -> None:
        """
        Starts the connection loop
        """
        if self._backpack_connected:
            message = "Backpack already connected"
            self._rhapi.ui.message_notify(self._rhapi.language.__(message))
            return

        id_ = self._rhapi.db.option("_conn_opt", None, as_int=True)
        for con in ConnectionTypeEnum:
            if id_ == con.id_:
                break
        else:
            message = "Connection type not provided"
            self._rhapi.ui.message_notify(self._rhapi.language.__(message))
            return

        if con == ConnectionTypeEnum.USB:
            self._establish_connection(con.type_)

        elif con == ConnectionTypeEnum.ONBOARD:
            if RH_GPIO.is_real_hw_GPIO():
                logger.info("Turning on GPIO pins for NuclearHazard boards")
                RH_GPIO.setmode(RH_GPIO.BCM)
                RH_GPIO.setup(16, RH_GPIO.OUT, initial=RH_GPIO.HIGH)
                gevent.sleep(0.5)
                RH_GPIO.setup(11, RH_GPIO.OUT, initial=RH_GPIO.HIGH)
                gevent.sleep(0.5)
                RH_GPIO.output(11, RH_GPIO.LOW)
                gevent.sleep()
                RH_GPIO.output(11, RH_GPIO.HIGH)

                self._establish_connection(con.type_)

            else:
                message = "Instance not running on Raspberry Pi"
                self._rhapi.ui.message_notify(self._rhapi.language.__(message))

        elif con == ConnectionTypeEnum.SOCKET:
            addr = self._rhapi.db.option("_socket_ip", None)
            if addr is not None:
                try:
                    ip_addr = socket.gethostbyname(addr)
                except socket.gaierror:
                    message = "Failed to connect to device's socket"
                    self._rhapi.ui.message_notify(self._rhapi.language.__(message))
                else:
                    self._establish_connection(con.type_, ip_addr=ip_addr)
            else:
                message = "IP Address for socket not provided"
                self._rhapi.ui.message_notify(self._rhapi.language.__(message))

    def _establish_connection(
        self, connection_type: type[BackpackConnection], **kwargs
    ):
        """
        Setup the backpack connection

        :param connection_type: The type of connection to use
        """
        # Clear data in send queue
        while not self._send_queue.empty():
            self._send_queue.get()

        self._connection = connection_type(self._send_queue, self._recieve_queue)
        if not self._connection.connect(**kwargs):
            message = "Attempt to establish backpack connection failed"
            self._rhapi.ui.message_notify(self._rhapi.language.__(message))
            return

        message = "Backpack sucessfully connected"
        self._rhapi.ui.message_notify(self._rhapi.language.__(message))

        self.version_request()

    def recieve_loop(self) -> None:
        """
        Handles recieving data from the backpack
        """
        try:
            while True:
                packet: MSPPacket = self._recieve_queue.get()

                function_ = packet.function

                if packet.type_ == MSPPacketType.RESPONSE:
                    if function_ == MSPTypes.MSP_ELRS_GET_BACKPACK_VERSION:
                        version = bytes(i for i in packet.payload if i != 0).decode(
                            "utf-8"
                        )
                        message = f"Backpack device firmware version: {version}"
                        logger.info(message)
                        self._rhapi.ui.message_notify(self._rhapi.language.__(message))

                if packet.type_ == MSPPacketType.COMMAND:
                    if function_ == MSPTypes.MSP_ELRS_BACKPACK_SET_RECORDING_STATE:
                        itr = packet.iterate_payload()
                        if (val := next(itr)) == 0x00:
                            self.stop_race()
                        elif val == 0x01:
                            self.start_race()

        except KeyboardInterrupt:
            logger.error("Stopping blackpack connector greenlet")

    def disconnect(self, *_) -> None:
        """
        Disconnect the connection loop
        """
        if not self._backpack_connected:
            message = "Backpack not connected"
            self._rhapi.ui.message_notify(self._rhapi.language.__(message))
            return

        assert self._connection is not None
        self._connection.disconnect()

        message = "Backpack disconnected"
        self._rhapi.ui.message_notify(self._rhapi.language.__(message))

    #
    # Packet creation
    #

    def hash_phrase(self, bindphrase: str) -> bytes:
        """
        Hashes a string into a UID

        :param bindphrase: The string to hash
        :return: The hashed phrase
        """

        hash_ = bytearray(
            x
            for x in hashlib.md5(
                (f'-DMY_BINDING_PHRASE="{bindphrase}"').encode()
            ).digest()[0:6]
        )
        if (hash_[0] % 2) == 1:
            hash_[0] -= 0x01

        return hash_

    def get_pilot_uid(self, pilot_id: int) -> bytes:
        """
        Get the uid for a pilot. If a bindphrase is not
        saved as an attribute, the pilot callsign is used
        to generate the uid.

        :param pilot_id: The pilot id
        :return: The pilot uid
        """
        assert pilot_id > 0, "Can not generate backpack uid for invalid pilot"
        bindphrase = self._rhapi.db.pilot_attribute_value(pilot_id, "comm_elrs")
        if bindphrase:
            uid = self.hash_phrase(bindphrase)
        else:
            pilot = self._rhapi.db.pilot_by_id(pilot_id)
            assert pilot is not None, "Pilot not in database"
            uid = self.hash_phrase(pilot.callsign)

        return uid

    def center_osd(self, len_: int) -> int:
        """
        Provides the column value needed to
        center a string of the provided length
        on the HDZero Goggles screen

        :param len_: The length of the string
        :return:
        """
        offset = len_ // 2
        col = 50 // 2 - offset
        return max(col, 0)

    def _pilot_on(self, pilot_id: int) -> bool:
        return self._rhapi.db.pilot_attribute_value(pilot_id, "elrs_active") == "1"

    def _active_pilot_ids(self) -> list[int]:
        out = []
        for seat, pilot_id in (self._rhapi.race.pilots or {}).items():
            if pilot_id and self._pilot_on(pilot_id):
                out.append(int(pilot_id))
        return out

    def _preload_layouts(self, pilot_ids=None) -> None:
        for pilot_id in pilot_ids or self._active_pilot_ids():
            self._pilot_layout(int(pilot_id))

    def _pilot_layout(self, pilot_id: int) -> dict | None:
        if pilot_id in self._osd_layouts:
            return self._osd_layouts[pilot_id]
        raw = None
        try:
            raw = self._rhapi.db.pilot_attribute_value(pilot_id, "comm_osd")
        except Exception:
            logger.exception("Failed to read comm_osd for pilot %s", pilot_id)
        if not raw:
            try:
                for attr in self._rhapi.db.pilot_attributes(pilot_id) or []:
                    name = getattr(attr, "name", "")
                    if name in ("comm_osd", "goggle_osd"):
                        value = getattr(attr, "value", None)
                        if value:
                            raw = value
                            break
            except Exception:
                logger.exception("Failed to list OSD attributes for pilot %s", pilot_id)
        layout = parse_comm_osd(raw)
        self._osd_layouts[pilot_id] = layout
        if layout:
            status = element(layout, "race_status")
            lap = element(layout, "lap_result")
            heat = element(layout, "heat_name")
            logger.info(
                "Pilot %s using FPV Scores OSD layout heat_row=%s arm_row=%s lap_row=%s",
                pilot_id,
                None if heat is None else heat.get("row"),
                None if status is None else status.get("row"),
                None if lap is None else lap.get("row"),
            )
        else:
            logger.info("Pilot %s using timer OSD settings", pilot_id)
        return layout

    def _item(
        self,
        layout: dict | None,
        item_id: str,
        *,
        fallback_on: bool = True,
        row: int = 0,
        hold_secs: int | None = None,
        num_laps: int = 3,
    ) -> dict | None:
        if layout is not None:
            return element(layout, item_id)
        if not fallback_on:
            return None
        return {
            "enabled": True,
            "row": max(0, min(17, int(row or 0))),
            "col": 0,
            "center": True,
            "hold_secs": hold_secs,
            "num_laps": max(1, min(5, int(num_laps or 3))),
        }

    def _coords(self, item: dict, text: str) -> tuple[int, int]:
        row = max(0, min(17, int(item.get("row") or 0)))
        if item.get("center", True):
            return row, self.center_osd(len(text))
        return row, max(0, min(49, int(item.get("col") or 0)))

    def _hold_seconds(self, item: dict | None, decaseconds_option: str | None = None) -> float:
        if item is None:
            return -1
        hold = item.get("hold_secs")
        if hold is None:
            if not decaseconds_option:
                return -1
            try:
                return max(0, int(self._rhapi.db.option(decaseconds_option))) * 0.1
            except (TypeError, ValueError):
                return 5
        try:
            return float(int(hold))
        except (TypeError, ValueError):
            return 5

    def _opt_int(self, name: str, default: int = 0) -> int:
        try:
            return int(self._rhapi.db.option(name))
        except (TypeError, ValueError):
            return default

    def _short_time(self, value) -> str:
        if value is None:
            return ""
        if isinstance(value, (int, float)):
            try:
                value = self._rhapi.utils.format_split_time_to_str(value, "{m}:{s}.{d}")
            except Exception:
                value = str(value)
        text = str(value).strip()
        if text.startswith("0:"):
            text = text[2:]
        if "." in text:
            whole, frac = text.split(".", 1)
            text = whole + "." + frac[:2]
        return text

    def _send_item(self, item: dict | None, text: str, label: str = "") -> int | None:
        if not item or not text:
            return None
        row, col = self._coords(item, text)
        logger.info(
            "OSD send %s row=%s col=%s %s",
            label or "item",
            row,
            col,
            text[:48],
        )
        self.send_osd_text(row, col, text)
        return row

    def _clear_rows(self, start_row: int, count: int = 1) -> None:
        for row in range(start_row, min(start_row + max(1, count), 18)):
            self.send_clear_osd_row(row)

    def _show_then_clear(
        self,
        uid: bytes,
        item: dict | None,
        text: str,
        decaseconds_option: str | None = None,
        rows: int = 1,
    ) -> None:
        if not item or not text:
            return
        row, col = self._coords(item, text)
        logger.info("OSD send row=%s col=%s %s", row, col, text[:48])
        with self._queue_lock:
            self.set_send_uid(uid)
            self.send_osd_text(row, col, text)
            self.send_display_osd()
            self.reset_send_uid()
        secs = self._hold_seconds(item, decaseconds_option)
        if secs < 0:
            return
        gevent.sleep(secs)
        with self._queue_lock:
            self.set_send_uid(uid)
            self._clear_rows(row, rows)
            self.send_display_osd()
            self.reset_send_uid()

    def send_msp(self, msp: MSPPacket) -> None:
        """
        Sends a MSP packet to the backpack connection
        if it is active

        :param msp: _description_
        """
        if self._backpack_connected:
            self._send_queue.put(msp)

    def set_send_uid(self, address: bytes) -> None:
        """
        Sends the packet to set the address for the
        recipient of future packets

        :param address: Address to set
        """
        packet = MSPPacket()
        packet.set_function(MSPTypes.MSP_ELRS_SET_SEND_UID)
        payload = bytearray()
        payload.append(0x01)
        payload += address
        packet.set_payload(payload)
        self.send_msp(packet)

    def reset_send_uid(self) -> None:
        """
        Sends the packet to reset the packet recipient
        to the system default
        """
        packet = MSPPacket()
        packet.set_function(MSPTypes.MSP_ELRS_SET_SEND_UID)
        payload = bytearray()
        payload.append(0x00)
        packet.set_payload(payload)
        self.send_msp(packet)

    def send_clear_osd(self) -> None:
        """
        Sends the packet to clear the goggle's osd
        """
        packet = MSPPacket()
        packet.set_function(MSPTypes.MSP_ELRS_SET_OSD)
        payload = bytearray()
        payload.append(0x02)
        packet.set_payload(payload)
        self.send_msp(packet)

    def send_osd_text(self, row: int, col: int, text: str) -> None:
        """
        Sends a packet that provides text data to the
        recipient. This does not display the text to the
        recipient until `send_display_osd` is called

        :param row: The row to display the text on
        :param col: The column to place the start of the
        :param message: _description_
        """
        payload = bytearray((0x03, row, col, 0))
        for index, char in enumerate(text):
            if index >= 50:
                break

            payload.append(ord(char))

        packet = MSPPacket()
        packet.set_function(MSPTypes.MSP_ELRS_SET_OSD)
        packet.set_payload(payload)
        self.send_msp(packet)

    def send_display_osd(self) -> None:
        """
        Sends a packet that informs the recipient
        to display any provided text
        """
        packet = MSPPacket()
        packet.set_function(MSPTypes.MSP_ELRS_SET_OSD)
        payload = bytearray((0x04,))
        packet.set_payload(payload)
        self.send_msp(packet)

    def send_clear_osd_row(self, row: int) -> None:
        """
        Sends a packet that clears the text data
        in a specific row. This does not remove
        the text until `send_display_osd` is called.

        :param row: The row to remove text from
        """
        payload = bytearray((0x03, row, 0, 0))
        for _ in range(50):
            payload.append(0)

        packet = MSPPacket()
        packet.set_function(MSPTypes.MSP_ELRS_SET_OSD)
        packet.set_payload(payload)
        self.send_msp(packet)

    def version_request(self):
        """
        Sends the packet requesting the version of the
        backpack hardware
        """
        packet = MSPPacket()
        packet.set_function(MSPTypes.MSP_ELRS_GET_BACKPACK_VERSION)
        self.send_msp(packet)

    def activate_bind(self, *_) -> None:
        """
        Sends a packet to put the connected device in
        bind mode
        """
        message = "Activating backpack's bind mode..."
        self._rhapi.ui.message_notify(self._rhapi.language.__(message))

        packet = MSPPacket()
        packet.set_function(MSPTypes.MSP_ELRS_BACKPACK_SET_MODE)
        payload = bytearray((ord("B"),))
        packet.set_payload(payload)
        self.send_msp(packet)

    def activate_wifi(self, *_) -> None:
        """
        Sends a packet to put the connected device in
        bind mode
        """
        message = "Turning on backpack's wifi..."
        self._rhapi.ui.message_notify(self._rhapi.language.__(message))

        packet = MSPPacket()
        packet.set_function(MSPTypes.MSP_ELRS_BACKPACK_SET_MODE)
        payload = bytearray((ord("W"),))
        packet.set_payload(payload)
        self.send_msp(packet)

    #
    # Field Tests
    #

    def test_bind_osd(self, *_):
        """
        A test for checking the connection of the pilot
        bound to the timer backpack
        """

        def test():
            self._queue_lock.acquire()
            text = "ROTORHAZARD"
            for row in range(18):
                self.send_clear_osd()
                start_col = self.center_osd(len(text))
                self.send_osd_text(row, start_col, text)
                self.send_display_osd()

                gevent.sleep(0.5)

                self.send_clear_osd_row(row)
                self.send_display_osd()

            gevent.sleep(1)
            self.send_clear_osd()
            self.send_display_osd()
            self._queue_lock.release()

        gevent.spawn(test)

    #
    # VRxC Event Triggers
    #

    def pilot_alter(self, args: dict) -> None:
        """
        Logs the uid change of the pilot

        :param args: _description_
        """
        pilot_id = args["pilot_id"]
        self._osd_layouts.pop(pilot_id, None)
        uid = self.get_pilot_uid(pilot_id)
        uid_formated = ".".join([str(int.from_bytes((byte,))) for byte in uid])
        logger.info("Pilot %s's UID set to %s", pilot_id, uid_formated)
        self._pilot_layout(pilot_id)

    def onRaceStage(self, args) -> None:
        if not self._backpack_connected:
            return
        self._preload_layouts()

        use_heat_name = self._rhapi.db.option("_heat_name") == "1"
        use_round_num = self._rhapi.db.option("_round_num") == "1"
        use_class_name = self._rhapi.db.option("_class_name") == "1"
        use_event_name = self._rhapi.db.option("_event_name") == "1"

        heat_data = self._rhapi.db.heat_by_id(args["heat_id"])
        if heat_data:
            class_id = heat_data.class_id
            heat_name = heat_data.display_name
            round_num = self._rhapi.db.heat_max_round(args["heat_id"]) + 1
        else:
            class_id = None
            heat_name = None
            round_num = None

        if class_id:
            raceclass = self._rhapi.db.raceclass_by_id(class_id)
            class_name = raceclass.display_name
        else:
            class_name = None

        event_name = self._rhapi.db.option("eventName")
        stage_text = self._rhapi.db.option("_racestage_message")

        def heat_text(include_round: bool) -> str:
            if not heat_name:
                return ""
            if include_round and round_num:
                round_trans = self._rhapi.__("Round")
                return f"x {heat_name.upper()} | {round_trans.upper()} {round_num} w"
            return f"x {heat_name.upper()} w"

        def arm(pilot_id):
            layout = self._pilot_layout(pilot_id)
            heat_item = self._item(
                layout,
                "heat_name",
                fallback_on=use_heat_name and bool(heat_name),
                row=self._opt_int("_heatname_row", 2),
            )
            class_item = self._item(
                layout,
                "class_name",
                fallback_on=use_class_name and bool(class_name),
                row=self._opt_int("_classname_row", 1),
            )
            event_item = self._item(
                layout,
                "event_name",
                fallback_on=use_event_name and bool(event_name),
                row=self._opt_int("_eventname_row", 0),
            )
            status_item = self._item(
                layout,
                "race_status",
                fallback_on=True,
                row=self._opt_int("_status_row", 5),
            )
            uid = self.get_pilot_uid(pilot_id)
            with self._queue_lock:
                self.set_send_uid(uid)
                self.send_clear_osd()
                self._send_item(status_item, stage_text, "race_status")
                include_round = True if layout is not None else use_round_num
                self._send_item(heat_item, heat_text(include_round), "heat_name")
                if class_name:
                    self._send_item(class_item, f"x {class_name.upper()} w", "class_name")
                if event_name:
                    self._send_item(event_item, f"x {str(event_name).upper()} w", "event_name")
                self.send_display_osd()
                self.reset_send_uid()

        seat_pilots = self._rhapi.race.pilots
        for seat in seat_pilots:
            if seat_pilots[seat] and self._pilot_on(seat_pilots[seat]):
                gevent.spawn(arm, seat_pilots[seat])

    def onRaceStart(self, *_) -> None:
        if not self._backpack_connected:
            return
        self._preload_layouts()

        def start(pilot_id):
            layout = self._pilot_layout(pilot_id)
            status_item = self._item(
                layout,
                "race_status",
                fallback_on=True,
                row=self._opt_int("_status_row", 5),
            )
            uid = self.get_pilot_uid(pilot_id)
            with self._queue_lock:
                self.set_send_uid(uid)
                self.send_clear_osd()
                self._send_item(status_item, self._rhapi.db.option("_racestart_message"), "race_status")
                self.send_display_osd()
                self.reset_send_uid()
            if not status_item:
                return
            secs = self._hold_seconds(status_item, "_racestart_uptime")
            if secs < 0:
                return
            gevent.sleep(secs)
            row, _ = self._coords(status_item, "x")
            with self._queue_lock:
                self.set_send_uid(uid)
                self.send_clear_osd_row(row)
                self.send_display_osd()
                self.reset_send_uid()

        seat_pilots = self._rhapi.race.pilots
        for seat in seat_pilots:
            if seat_pilots[seat] and self._pilot_on(seat_pilots[seat]):
                gevent.spawn(start, seat_pilots[seat])

    def onRaceFinish(self, *_) -> None:
        if not self._backpack_connected:
            return
        self._preload_layouts()

        def finish(pilot_id):
            layout = self._pilot_layout(pilot_id)
            status_item = self._item(
                layout,
                "race_status",
                fallback_on=True,
                row=self._opt_int("_status_row", 5),
            )
            uid = self.get_pilot_uid(pilot_id)
            self._show_then_clear(
                uid,
                status_item,
                self._rhapi.db.option("_racefinish_message"),
                "_finish_uptime",
            )

        seat_pilots = self._rhapi.race.pilots
        seats_finished = self._rhapi.race.seats_finished

        for seat in seat_pilots:
            if (
                seat_pilots[seat]
                and self._pilot_on(seat_pilots[seat])
                and not seats_finished[seat]
            ):
                gevent.spawn(finish, seat_pilots[seat])

    def onRaceStop(self, *_) -> None:
        if not self._backpack_connected:
            return
        self._preload_layouts()

        def land(pilot_id):
            layout = self._pilot_layout(pilot_id)
            status_item = self._item(
                layout,
                "race_status",
                fallback_on=True,
                row=self._opt_int("_status_row", 5),
            )
            uid = self.get_pilot_uid(pilot_id)
            self._show_then_clear(
                uid,
                status_item,
                self._rhapi.db.option("_racestop_message"),
                "_finish_uptime",
            )

        seat_pilots = self._rhapi.race.pilots
        seats_finished = self._rhapi.race.seats_finished

        for seat in seat_pilots:
            if (
                seat_pilots[seat]
                and self._pilot_on(seat_pilots[seat])
                and not seats_finished[seat]
            ):
                gevent.spawn(land, seat_pilots[seat])

    def _lap_time_message(self, gap_info) -> str:
        if gap_info.race.win_condition == WinCondition.FASTEST_CONSECUTIVE:
            formatted_time1 = self._rhapi.utils.format_split_time_to_str(
                gap_info.current.last_lap_time, "{m}:{s}.{d}"
            )
            formatted_time2 = self._rhapi.utils.format_split_time_to_str(
                gap_info.current.consecutives, "{m}:{s}.{d}"
            )
            return f"x {formatted_time1} | {gap_info.current.consecutives_base}/{formatted_time2} w"
        if gap_info.race.win_condition == WinCondition.FASTEST_LAP and getattr(
            gap_info.current, "is_best", gap_info.current.is_best_lap
        ):
            formatted_time = self._rhapi.utils.format_split_time_to_str(
                gap_info.current.last_lap_time, "{m}:{s}.{d}"
            )
            return f"x BEST LAP | {formatted_time} w"
        formatted_time1 = self._rhapi.utils.format_split_time_to_str(
            gap_info.current.last_lap_time, "{m}:{s}.{d}"
        )
        formatted_time2 = self._rhapi.utils.format_split_time_to_str(
            gap_info.current.total_time_laps, "{m}:{s}.{d}"
        )
        return f"x {formatted_time1} | {formatted_time2} w"

    def _gap_ahead_message(self, gap_info) -> str:
        if gap_info.race.win_condition == WinCondition.FASTEST_CONSECUTIVE:
            formatted_time1 = self._rhapi.utils.format_split_time_to_str(
                gap_info.current.last_lap_time, "{m}:{s}.{d}"
            )
            formatted_time2 = self._rhapi.utils.format_split_time_to_str(
                gap_info.current.consecutives, "{m}:{s}.{d}"
            )
            return f"x {formatted_time1} | {gap_info.current.consecutives_base}/{formatted_time2} w"
        if gap_info.race.win_condition == WinCondition.FASTEST_LAP:
            if gap_info.next_rank.diff_time:
                formatted_time = self._rhapi.utils.format_split_time_to_str(
                    gap_info.next_rank.diff_time, "{m}:{s}.{d}"
                )
                return f"x {str.upper(gap_info.next_rank.callsign)} | +{formatted_time} w"
            if gap_info.current.is_best_lap and gap_info.current.lap_number:
                formatted_time = self._rhapi.utils.format_split_time_to_str(
                    gap_info.current.last_lap_time, "{m}:{s}.{d}"
                )
                return f"x {self._rhapi.db.option('_leader_message')} | {formatted_time} w"
            if gap_info.current.lap_number:
                formatted_time = self._rhapi.utils.format_split_time_to_str(
                    gap_info.first_rank.diff_time, "{m}:{s}.{d}"
                )
                return f"x {str.upper(gap_info.first_rank.callsign)} | +{formatted_time} w"
            return ""
        if gap_info.next_rank.diff_time:
            formatted_time = self._rhapi.utils.format_split_time_to_str(
                gap_info.next_rank.diff_time, "{m}:{s}.{d}"
            )
            return f"x {str.upper(gap_info.next_rank.callsign)} | +{formatted_time} w"
        if gap_info.current.lap_number:
            formatted_time = self._rhapi.utils.format_split_time_to_str(
                gap_info.current.last_lap_time, "{m}:{s}.{d}"
            )
            return f"x {self._rhapi.db.option('_leader_message')} | {formatted_time} w"
        return ""

    def _gap_behind_message(self, result: dict, leaderboard: list) -> str:
        try:
            pos = int(result.get("position"))
        except (TypeError, ValueError):
            return ""
        behind = None
        for other in leaderboard or []:
            try:
                if int(other.get("position")) == pos + 1:
                    behind = other
                    break
            except (TypeError, ValueError):
                continue
        if not behind:
            return ""
        callsign = str(behind.get("callsign") or "").upper()
        formatted = ""
        try:
            cur = result.get("total_time_raw")
            oth = behind.get("total_time_raw")
            if cur and oth:
                formatted = self._rhapi.utils.format_split_time_to_str(
                    abs(int(oth) - int(cur)), "{m}:{s}.{d}"
                )
        except (TypeError, ValueError):
            formatted = ""
        if formatted:
            return f"x {callsign} | -{formatted} w"
        return f"x {callsign} w"

    def _position_message(self, result: dict, layout: dict | None) -> str:
        laps = int(result.get("laps") or 0) + 1
        if layout is not None or self._rhapi.db.option("_position_mode") == "1":
            return f"POSN: {str(result.get('position')).upper()} | LAP: {laps}"
        return f"LAP: {laps}"

    def _recent_lap_lines(self, gap_info, count: int) -> list[str]:
        node = getattr(getattr(gap_info, "current", None), "lap_list", None)
        laps = []
        if isinstance(node, dict):
            laps = node.get("laps") or []
        elif isinstance(node, list):
            laps = node
        lines = []
        for lap in laps:
            if not isinstance(lap, dict) or lap.get("deleted"):
                continue
            num = lap.get("lap_number")
            time_s = self._short_time(lap.get("lap_time_formatted") or lap.get("lap_time"))
            if num in (0, None) and not lines:
                label = "HS"
            elif num in (0, -1) or num is None:
                label = "HS" if not lines else f"L{len(lines)}"
            else:
                label = f"L{num}"
            lines.append(f"{label} {time_s}".strip())
        return lines[-max(1, count) :]

    def onRaceLapRecorded(self, args: dict) -> None:
        if not self._backpack_connected:
            return
        self._preload_layouts()

        def update_pos(result):
            pilot_id = result["pilot_id"]
            layout = self._pilot_layout(pilot_id)
            item = self._item(
                layout,
                "lap_position",
                fallback_on=True,
                row=self._opt_int("_currentlap_row", 0),
            )
            if not item:
                return
            message = self._position_message(result, layout)
            uid = self.get_pilot_uid(pilot_id)
            row, col = self._coords(item, message)
            with self._queue_lock:
                self.set_send_uid(uid)
                self.send_clear_osd_row(row)
                self.send_osd_text(row, col, message)
                self.send_display_osd()
                self.reset_send_uid()

        def update_recent(result, gap_info):
            if gap_info is None:
                return
            pilot_id = result["pilot_id"]
            layout = self._pilot_layout(pilot_id)
            item = self._item(layout, "recent_laps", fallback_on=False)
            if not item:
                return
            count = max(1, min(5, int(item.get("num_laps") or 3)))
            lines = self._recent_lap_lines(gap_info, count)
            if not lines:
                return
            uid = self.get_pilot_uid(pilot_id)
            start_row = max(0, min(17, int(item.get("row") or 0)))
            with self._queue_lock:
                self.set_send_uid(uid)
                self._clear_rows(start_row, count)
                for offset, line in enumerate(lines):
                    row = min(17, start_row + offset)
                    col = (
                        self.center_osd(len(line))
                        if item.get("center", True)
                        else max(0, min(49, int(item.get("col") or 0)))
                    )
                    self.send_osd_text(row, col, line)
                self.send_display_osd()
                self.reset_send_uid()

        def lap_results(result, gap_info):
            pilot_id = result["pilot_id"]
            layout = self._pilot_layout(pilot_id)
            gap_on = self._rhapi.db.option("_gap_mode") == "1"
            lap_item = self._item(
                layout,
                "lap_result",
                fallback_on=not gap_on,
                row=self._opt_int("_lapresults_row", 15),
            )
            gap_item = self._item(
                layout,
                "gap_result",
                fallback_on=gap_on,
                row=self._opt_int("_lapresults_row", 15),
            )
            behind_item = self._item(layout, "gap_behind", fallback_on=False)
            uid = self.get_pilot_uid(pilot_id)
            if lap_item:
                gevent.spawn(
                    self._show_then_clear,
                    uid,
                    lap_item,
                    self._lap_time_message(gap_info),
                    "_results_uptime",
                )
            if gap_item:
                gevent.spawn(
                    self._show_then_clear,
                    uid,
                    gap_item,
                    self._gap_ahead_message(gap_info),
                    "_results_uptime",
                )
            if behind_item:
                gevent.spawn(
                    self._show_then_clear,
                    uid,
                    behind_item,
                    self._gap_behind_message(result, args["results"].get("by_race_time") or []),
                    "_results_uptime",
                )

        seats_finished = self._rhapi.race.seats_finished
        pilots_completion = {}
        for slot, pilot_id in self._rhapi.race.pilots.items():
            if pilot_id:
                pilots_completion[pilot_id] = seats_finished[slot]

        results = args["results"]["by_race_time"]
        for result in results:
            if self._pilot_on(result["pilot_id"]) and not pilots_completion[result["pilot_id"]]:
                gevent.spawn(update_pos, result)
                if result["pilot_id"] == args["pilot_id"]:
                    gevent.spawn(update_recent, result, args.get("gap_info"))
                    if result["laps"] > 0:
                        gevent.spawn(lap_results, result, args["gap_info"])

    def onLapDelete(self, *_) -> None:
        """
        Update a pilot's OSD when a they have finished
        """
        if not self._backpack_connected:
            return

        def delete(pilot_id):
            uid = self.get_pilot_uid(pilot_id)
            self._queue_lock.acquire()
            self.set_send_uid(uid)
            self.send_clear_osd()
            self.send_display_osd()
            self.reset_send_uid()
            self._queue_lock.release()

        seat_pilots = self._rhapi.race.pilots
        for seat in seat_pilots:
            if not seat_pilots[seat] or not self._pilot_on(seat_pilots[seat]):
                continue
            layout = self._pilot_layout(seat_pilots[seat])
            results_item = self._item(
                layout,
                "results",
                fallback_on=self._rhapi.db.option("_results_mode") == "1",
                row=self._opt_int("_results_row", 13),
            )
            if results_item:
                gevent.spawn(delete, seat_pilots[seat])

    def onRacePilotDone(self, args: dict) -> None:
        """
        Update a pilot's OSD when a they have finished
        """
        if not self._backpack_connected:
            return
        self._preload_layouts()

        def done(result, win_condition):
            pilot_id = result["pilot_id"]
            layout = self._pilot_layout(pilot_id)
            status_item = self._item(
                layout,
                "race_status",
                fallback_on=True,
                row=self._opt_int("_status_row", 5),
            )
            pos_item = self._item(
                layout,
                "lap_position",
                fallback_on=True,
                row=self._opt_int("_currentlap_row", 0),
            )
            results_item = self._item(
                layout,
                "results",
                fallback_on=self._rhapi.db.option("_results_mode") == "1",
                row=self._opt_int("_results_row", 13),
            )
            uid = self.get_pilot_uid(pilot_id)
            with self._queue_lock:
                self.set_send_uid(uid)
                if pos_item:
                    self.send_clear_osd_row(int(pos_item.get("row") or 0))
                self._send_item(status_item, self._rhapi.db.option("_pilotdone_message"), "race_status")
                if results_item:
                    placement_message = f"PLACEMENT: {result['position']}"
                    self._send_item(results_item, placement_message, "results")
                    if win_condition == WinCondition.FASTEST_CONSECUTIVE:
                        win_message = f"FASTEST {result['consecutives_base']} CONSEC: {result['consecutives']}"
                    elif win_condition == WinCondition.FASTEST_LAP:
                        win_message = f"FASTEST LAP: {result['fastest_lap']}"
                    elif win_condition == WinCondition.FIRST_TO_LAP_X:
                        win_message = f"TOTAL TIME: {result['total_time']}"
                    else:
                        win_message = f"LAPS COMPLETED: {result['laps']}"
                    win_item = dict(results_item)
                    win_item["row"] = min(17, int(results_item.get("row") or 0) + 1)
                    self._send_item(win_item, win_message, "results")
                self.send_display_osd()
                self.reset_send_uid()

            secs = self._hold_seconds(status_item, "_finish_uptime")
            if status_item and secs >= 0:
                gevent.sleep(secs)
                row, _ = self._coords(status_item, "x")
                with self._queue_lock:
                    self.set_send_uid(uid)
                    self.send_clear_osd_row(row)
                    self.send_display_osd()
                    self.reset_send_uid()

        results = args["results"]
        leaderboard = results[results["meta"]["primary_leaderboard"]]
        for result in leaderboard:
            if self._pilot_on(args["pilot_id"]) and result["pilot_id"] == args["pilot_id"]:
                gevent.spawn(done, result, results["meta"]["win_condition"])
                break

    def onLapsClear(self, *_) -> None:
        """
        Removes data from pilot's OSD when laps are removed from the system
        """
        if not self._backpack_connected:
            return

        def clear(pilot_id):
            uid = self.get_pilot_uid(pilot_id)
            self._queue_lock.acquire()
            self.set_send_uid(uid)
            self.send_clear_osd()
            self.send_display_osd()
            self.reset_send_uid()
            self._queue_lock.release()

        seat_pilots = self._rhapi.race.pilots
        for seat in seat_pilots:
            if seat_pilots[seat] and self._pilot_on(seat_pilots[seat]):
                gevent.spawn(clear, seat_pilots[seat])

    def onSendMessage(self, args: dict | None = None) -> None:
        """
        Sends custom text to pilots of the active heat
        """
        if not self._backpack_connected:
            return

        if args is None:
            return
        self._preload_layouts()

        def notify(pilot):
            layout = self._pilot_layout(pilot)
            item = self._item(
                layout,
                "announcement",
                fallback_on=True,
                row=self._opt_int("_announcement_row", 3),
            )
            uid = self.get_pilot_uid(pilot)
            self._show_then_clear(
                uid,
                item,
                f"x {str.upper(args['message'])} w",
                "_announcement_uptime",
            )

        seat_pilots = self._rhapi.race.pilots
        for seat in seat_pilots:
            if seat_pilots[seat] and self._pilot_on(seat_pilots[seat]):
                gevent.spawn(notify, seat_pilots[seat])
