# -*- coding: utf-8 -*-
"""Executable model of the FNIRSI 2C53T MCU<->FPGA boundary.

This is the growing, testable artifact at the center of the FPGA
emulation oracle (see notes/renode-at32-bringup.md). The opaque Gowin
FPGA can only be reverse engineered through how the AT32F403A firmware
talks to it; this module encodes our current best hypothesis of the
FPGA's *response* contract so the real firmware can be booted against it
in Renode and driven down its acquisition path.

Design rules:
  - 2/3-compatible, stdlib-only. It must import cleanly under both
    `uv run python` (CPython) and Renode's embedded IronPython 2.7.
    No f-strings, no type hints, no walrus, no pathlib.
  - STRUCTURE is static-inferred from notes/scope_acquisition_spec.md
    (which functions / opcodes / handshake ordering). Reply VALUES that
    we have not seen on real silicon are returned as documented
    placeholders and tagged unverified=True in the access log. Do not
    promote a placeholder to "known" without a hardware or higher-
    confidence trace (confidence discipline).

Seed facts (from scope_acquisition_spec.md, V1.2.0):
  - SPI3 @ 0x40003C00, Mode 3, master, /2. Full-duplex: each xfer writes
    DT and reads the byte clocked in during that write.
  - CS = PB6 (active LOW), Enable = PC6 (HIGH), gate = PB11 (HIGH).
    Both PC6 and PB11 must be HIGH before SPI3 returns real data.
  - Handshake (2 bytes per CS assertion): 0x05 status/ID query, then
    0x12, then 0x15 post-handshake commands.
  - Bulk cal upload: 0x3B "begin", 38546 3-byte records (115638 bytes),
    0x3A "end". UNTIL this upload completes, MISO is idle-HIGH (0xFF) —
    the FPGA SPI data interface is inactive.

Oracle aid: set env RIPCORD_FPGA_SAMPLE_PATTERN=1 to make idle DT reads
return an incrementing counter instead of 0xFF. This is NOT a real FPGA
value — it lets the function-level oracle prove the sample read->buffer
data path (e.g. acq_engine_task burst into state+0x5B0) by making each
clocked-in byte distinguishable. Off by default so boot traces keep the
documented MISO-idle-HIGH behavior.
"""

import os

# --- SPI3 (STM32F1/AT32 SPI) register offsets, relative to 0x40003C00 ---
SPI_CTL0 = 0x00   # CR1
SPI_CTL1 = 0x04   # CR2
SPI_STS  = 0x08   # SR  (status)
SPI_DT   = 0x0C   # DR  (data)

# SPI status bits we assert so polled transfers always make progress.
SPI_STS_RXNE = 0x01
SPI_STS_TXE  = 0x02
SPI_STS_BSY  = 0x80
SPI_STS_READY = SPI_STS_TXE | SPI_STS_RXNE   # TXE + RXNE, BSY clear

# --- USART2 (STM32F1/AT32 USART) register offsets, relative to 0x40004400 ---
USART_STS = 0x00  # SR
USART_DT  = 0x04  # DR
USART_STS_RXNE = 0x20
USART_STS_TC   = 0x40
USART_STS_TXE  = 0x80
USART_STS_TXREADY = USART_STS_TXE | USART_STS_TC

# Idle MISO level before the FPGA data interface is brought up.
MISO_IDLE = 0xFF

# Known handshake command opcodes (structure, not reply values).
CMD_ID_QUERY   = 0x05
CMD_POST_12    = 0x12
CMD_POST_15    = 0x15
CMD_BULK_BEGIN = 0x3B
CMD_BULK_END   = 0x3A


class FpgaModel(object):
    """Stateful model of the FPGA as seen across the MCU bus boundary.

    One instance is held for the lifetime of an emulation run. Renode's
    SPI3/USART2 stub peripherals route DT writes/reads and status polls
    through this object; the execution tracer records the raw transcript
    independently, so this class does not need to log for capture — its
    `access_log` is for in-loop debugging and unverified-value auditing.
    """

    def __init__(self):
        self.cs_asserted = False     # PB6 LOW
        self.pc6_high = False        # SPI3 enable line
        self.pb11_high = False       # acquisition gate
        self.cal_uploaded = False    # bulk cal table applied
        self._bulk_mode = False
        self._bulk_count = 0
        self._last_cmd = None
        self._miso_next = MISO_IDLE  # byte the next DT read returns
        self._sample_ctr = 0         # incrementing sample placeholder (pattern mode)
        self._pattern = bool(os.environ.get("RIPCORD_FPGA_SAMPLE_PATTERN"))
        self.access_log = []         # list of dicts, for debugging

    # -- GPIO handshake lines (driven via the GPIO stub) ------------------
    def set_cs(self, asserted):
        self.cs_asserted = bool(asserted)

    def set_pc6(self, high):
        self.pc6_high = bool(high)

    def set_pb11(self, high):
        self.pb11_high = bool(high)

    def _data_interface_live(self):
        # The FPGA only returns real sample/handshake data once it is
        # enabled (PC6), gated (PB11), and the cal table is loaded.
        return self.pc6_high and self.pb11_high and self.cal_uploaded

    # -- SPI3 -------------------------------------------------------------
    def spi_status(self):
        return SPI_STS_READY

    def spi_write_dt(self, tx):
        """MCU clocks out `tx`; compute the byte that will be read back."""
        tx = tx & 0xFF
        unverified = True
        note = ""

        if self._bulk_mode:
            if tx == CMD_BULK_END:
                self._bulk_mode = False
                self.cal_uploaded = True
                note = "bulk_end after %d bytes" % self._bulk_count
                self._miso_next = MISO_IDLE
            else:
                self._bulk_count += 1
                self._miso_next = MISO_IDLE
                note = "bulk_byte"
        elif tx == CMD_BULK_BEGIN:
            self._bulk_mode = True
            self._bulk_count = 0
            self._miso_next = MISO_IDLE
            note = "bulk_begin"
        elif tx == CMD_ID_QUERY:
            # The MCU expects an FPGA status/ID byte here. The true value
            # has NOT been observed on silicon — placeholder, flagged.
            self._miso_next = MISO_IDLE
            note = "id_query -> UNVERIFIED reply"
        elif tx in (CMD_POST_12, CMD_POST_15):
            self._miso_next = MISO_IDLE
            note = "post_handshake_cmd -> UNVERIFIED reply"
        else:
            # Default: live data interface streams sample bytes; otherwise
            # idle-HIGH. Real sample values come from a hardware trace.
            self._miso_next = 0x00 if self._data_interface_live() else MISO_IDLE
            note = "data" if self._data_interface_live() else "pre-cal idle"

        self._last_cmd = tx
        self.access_log.append({
            "iface": "spi3", "dir": "write", "tx": tx,
            "rx_next": self._miso_next, "unverified": unverified, "note": note,
        })

    def spi_read_dt(self):
        """Return the byte clocked in during the most recent xfer."""
        rx = self._miso_next
        # After a non-bulk read the interface idles again unless streaming.
        if not self._data_interface_live():
            # Pattern mode: hand back a distinguishable incrementing byte so
            # the oracle can trace each sample byte into the MCU buffer.
            if self._pattern and not self._bulk_mode:
                rx = self._sample_ctr & 0xFF
                self._sample_ctr += 1
            self._miso_next = MISO_IDLE
        self.access_log.append({
            "iface": "spi3", "dir": "read", "rx": rx,
            "unverified": True, "note": "",
        })
        return rx & 0xFF

    # -- USART2 (early/command channel) -----------------------------------
    def usart_status(self):
        # TX always ready; RXNE only when we have queued an FPGA reply.
        return USART_STS_TXREADY

    def usart_write_dt(self, tx):
        self.access_log.append({
            "iface": "usart2", "dir": "write", "tx": tx & 0xFF,
            "unverified": False, "note": "mcu->fpga cmd byte",
        })

    def usart_read_dt(self):
        # No verified FPGA->MCU USART replies modeled yet.
        self.access_log.append({
            "iface": "usart2", "dir": "read", "rx": 0x00,
            "unverified": True, "note": "UNVERIFIED",
        })
        return 0x00

    # -- audit ------------------------------------------------------------
    def unverified_count(self):
        n = 0
        for e in self.access_log:
            if e.get("unverified"):
                n += 1
        return n


def _selftest():
    """Replay the documented handshake; runnable without Renode."""
    m = FpgaModel()
    # Bring up enable + gate (GPIO stub would do this).
    m.set_pc6(True)
    m.set_pb11(True)

    # Pre-cal: SPI data interface must be idle-HIGH.
    m.set_cs(True)
    m.spi_write_dt(CMD_ID_QUERY)
    assert m.spi_read_dt() == MISO_IDLE, "pre-cal MISO must be idle-HIGH"

    # Bulk cal upload: 0x3B begin, N data bytes, 0x3A end.
    m.spi_write_dt(CMD_BULK_BEGIN)
    for _ in range(115638):
        m.spi_write_dt(0xAB)
    assert not m.cal_uploaded, "cal not applied until bulk_end"
    m.spi_write_dt(CMD_BULK_END)
    assert m.cal_uploaded, "cal applied after bulk_end"
    assert m._bulk_count == 115638, "byte count tracked"

    # Post-cal with interface live: data path returns non-idle.
    m.spi_write_dt(0x00)
    assert m.spi_read_dt() == 0x00, "live data interface streams"

    print("fpga_protocol selftest OK")
    print("  bulk bytes uploaded : %d" % m._bulk_count)
    print("  total bus accesses  : %d" % len(m.access_log))
    print("  unverified accesses : %d (need a hardware/Renode trace to confirm)"
          % m.unverified_count())


if __name__ == "__main__":
    _selftest()
