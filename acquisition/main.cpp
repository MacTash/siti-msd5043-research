// MStar ISP read-only SPI NOR reader for SITI CCH-8000DEI (MSD5043 / Kronus).
// Read-only by design: this firmware implements NO flash write/erase path.
//
// Wiring (ESP32 DevKit V1):
//   GPIO17 -> SITI RX-pin side of the ISP SCL net (SITI RX + ISP SCL)
//   GPIO16 -> SITI TX-pin side of the ISP SDA net (SITI TX + ISP SDA)
//   GND    -> SITI GND
//   ISP is open-drain I2C; bus MUST have pull-ups (external 4.7k to the SITI
//   3.3V rail recommended if the board provides none).
//
// Host protocol (UART0, 921600 8N1):
//   PING                     -> PONG
//   INFO                     -> INFO msp-isp-reader fw=1 mode=READ-ONLY
//   SCAN                     -> FOUND 0x49 ... ; DONE   (I2C addresses 3..0x77)
//   SYNC                     -> OK                      (re-send "MSTAR" sync)
//   SERDBSYNC                -> SERDB OK                (sends "SERDB" sync to 0x5A only)
//   SERDBVERSION           -> SERDBVERSION OK reg=0xHH  (REG_CHIP_VERSION, 1-byte read; read-only)
//   SERDBPROBE               -> SERDBPROBE OK reg=0xHH  (activation + ch3 + 1-byte reg read; read-only)
//   SERDBTRACE               -> SERDBTRACE OK reg0=0xHH reg1=0xHH reg2=0xHH (3 documented reads; read-only)
//   SERDBDUMP 3|4          -> R <addr4hex> <name> 0xHH per allowlist entry / E on read failure,
//                             then SERDBDUMP OK ch=<n> ok=<k> fail=<f>
//                             (allowlist-built-in, read-only; entries/classes generated)
//   ID                       -> JEDEC EF4018            (via ISP, read-only)
//   READ <off_hex> <len_hex> -> DATA <len_hex>\n <len> raw bytes SUM32 <crc32>\n END\n
//   EXIT                     -> BYE               (sends 0x24; ends the ISP session)
//   An ISP session stays open across commands once entered (MSTAR sent once);
//   reads never issue 0x24. Only EXIT does.
//   anything else            -> ERR unknown <cmd>
//   D lines ("D ...") are diagnostics on the same channel: host prints them
//   to stderr; data block parsing never depends on them.
//
// MStar ISP protocol (verified against flashrom mstarddc_spi.c):
//   enable        : I2C write {M S T A R}
//   SPI cmd phase : I2C write {0x10} + <spi opcode + args>   (max 256 B payload)
//   SPI data phase: repeated-start I2C write {0x11}, then read N bytes
//   end           : I2C write {0x12}
//   exit          : I2C write {0x24}
//
// CRC32 is IEEE (reflected, poly 0xEDB88320), same as zlib.crc32.

#include <Arduino.h>
#include <Wire.h>
#include <esp_system.h>
#include "serdb_allowlist.h"

static const uint8_t  ISP_ADDR        = 0x49;
static const uint8_t  SERDB_ADDR      = 0x5A;   // Kronus SERDB (debug bus)
static const uint8_t  ISP_CMD_WRITE   = 0x10;
static const uint8_t  ISP_CMD_READ    = 0x11;
static const uint8_t  ISP_CMD_END     = 0x12;
static const uint8_t  ISP_CMD_RESET   = 0x24;

static const uint8_t  SDA_PIN         = 16;
static const uint8_t  SCL_PIN         = 17;
static const uint32_t I2C_CLOCK_HZ    = 100000;   // standard mode, kronus PSI spec is 100 kHz
static const uint32_t HOST_BAUD       = 921600;   // CP2102 supports this; SITI uses its own link

static const size_t   SPI_CHUNK       = 128;      // bytes per ISP read transaction
static const size_t   FLASH_BYTES     = 0x1000000UL;
static const int      ISP_TRIES       = 3;

static uint32_t crc32_table[256];
void crc32_init(void) {
  for (uint32_t i = 0; i < 256; i++) {
    uint32_t c = i;
    for (int k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320UL ^ (c >> 1)) : (c >> 1);
    crc32_table[i] = c;
  }
}
uint32_t crc32_update(uint32_t crc, const uint8_t *data, size_t n) {
  for (size_t i = 0; i < n; i++) crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
  return crc;
}
uint32_t crc32_ieee(const uint8_t *data, size_t n) {
  return crc32_update(0xFFFFFFFFUL, data, n) ^ 0xFFFFFFFFUL;
}

// Wire.endTransmission() return codes on the espressif32@6.9.0 Arduino core
// (framework-arduinoespressif32, IDF 4.4.x). The generic Arduino mapping
// (1=too long, 2=addr NACK, 3=data NACK) does NOT apply: endTransmission()
// returns 0 on ESP_OK, 2 on ESP_FAIL (which is what the IDF reports for an
// I2C NACK, address or data byte, with ack_check_en=true), 5 on
// ESP_ERR_TIMEOUT (bus busy), 4 on any other error. Address-NACK and
// data-NACK are not distinguishable through this API. Wire.write() returns
// 1 when the byte was queued in the TX buffer, 0 when the buffer is full.
struct I2cTxResult {
  uint8_t rc;       // raw Wire.endTransmission() status
  size_t  queued;   // bytes accepted into the Wire TX buffer
};

static I2cTxResult i2c_write_diag(const uint8_t *data, size_t n, uint8_t addr = ISP_ADDR) {
  Wire.beginTransmission(addr);
  size_t queued = 0;
  for (size_t i = 0; i < n; i++) {
    if (Wire.write(data[i]) != 1) break;
    queued++;
  }
  return { Wire.endTransmission(), queued };
}

static bool i2c_write(const uint8_t *data, size_t n) {
  return i2c_write_diag(data, n).rc == 0;
}

static bool i2c_write_read(const uint8_t *cmd, size_t cmd_len, uint8_t *out, size_t read_len) {
  Wire.beginTransmission(ISP_ADDR);
  for (size_t i = 0; i < cmd_len; i++) {
    if (Wire.write(cmd[i]) != 1) return false;
  }
  if (Wire.endTransmission(false) != 0) return false;   // repeated start, no stop
  size_t got = Wire.requestFrom((uint8_t)ISP_ADDR, (uint8_t)read_len, (uint8_t)true);
  if (got != read_len) return false;
  for (size_t i = 0; i < read_len; i++) out[i] = Wire.read();
  return true;
}

// ISP session state. The SITI's ISP slave is unreliable at re-entering ISP
// mode after an exit (0x24), so we hold the session open across commands and
// only leave ISP mode on the explicit EXIT command. 0x12 (end of SPI
// transaction) is still sent after every transaction, unchanged.
static bool isp_session_active = false;

static bool isp_enter(void) {
  if (isp_session_active) {
    Serial.printf("D isp_enter session=active\n");
    return true;
  }
  const uint8_t magic[5] = {'M', 'S', 'T', 'A', 'R'};
  I2cTxResult m = i2c_write_diag(magic, sizeof(magic));
  uint8_t end_rc = 255;        // 255 = fallback 0x12 not attempted
  size_t end_queued = 0;
  if (m.rc != 0) {
    // Already in ISP mode? Try END and continue, per mstarddc behaviour.
    const uint8_t end_cmd = ISP_CMD_END;
    I2cTxResult e = i2c_write_diag(&end_cmd, 1);
    end_rc = e.rc;
    end_queued = e.queued;
  }
  Serial.printf("D isp_enter MSTAR_rc=%u MSTAR_queued=%u END_rc=%u END_queued=%u\n",
                m.rc, (unsigned)m.queued, end_rc, (unsigned)end_queued);
  if (m.rc == 0 || end_rc == 0) {
    isp_session_active = true;
    return true;
  }
  return false;    // session not opened; state stays as-is (false)
}

static bool isp_exit(void) {
  if (!isp_session_active) {
    Serial.printf("D isp_exit session=inactive\n");
    return true;
  }
  const uint8_t reset_cmd = ISP_CMD_RESET;
  I2cTxResult r = i2c_write_diag(&reset_cmd, 1);
  Serial.printf("D isp_exit rc=%u queued=%u\n", r.rc, (unsigned)r.queued);
  if (r.rc == 0) {
    isp_session_active = false;
    return true;
  }
  return false;    // exit NOT clean: session deliberately left marked active
}

static bool isp_transact(const uint8_t *cmd, size_t cmd_len, uint8_t *out, size_t read_len) {
  uint8_t buf[9];
  if (cmd_len + 1 > sizeof(buf)) return false;
  buf[0] = ISP_CMD_WRITE;
  memcpy(buf + 1, cmd, cmd_len);
  if (!i2c_write(buf, cmd_len + 1)) return false;
  if (read_len) {
    const uint8_t rd = ISP_CMD_READ;
    if (!i2c_write_read(&rd, 1, out, read_len)) return false;
  }
  const uint8_t end_cmd = ISP_CMD_END;
  return i2c_write(&end_cmd, 1);
}

static bool isp_read(uint32_t addr, uint8_t *out, size_t n) {
  uint8_t cmd[4] = {0x03, (uint8_t)(addr >> 16), (uint8_t)(addr >> 8), (uint8_t)addr};
  return isp_transact(cmd, 4, out, n);
}

static bool isp_read_retry(uint32_t addr, uint8_t *out, size_t n) {
  for (int t = 0; t < ISP_TRIES; t++) {
    if (isp_read(addr, out, n)) return true;
    delay(2);
  }
  return false;
}

// SERDB activation only: sends the 5-byte sync in ONE I2C transaction.
// No SERDB commands of any kind are issued (no stop/resume MCU, no bus
// access, no exit, no register or memory writes).
static bool serdb_sync(void) {
  const uint8_t magic[5] = {'S', 'E', 'R', 'D', 'B'};
  I2cTxResult r = i2c_write_diag(magic, sizeof(magic), SERDB_ADDR);
  Serial.printf("D serdb_sync rc=%u queued=%u\n", r.rc, (unsigned)r.queued);
  return r.rc == 0 && r.queued == 5;
}

static bool isp_jedec(uint8_t id[3]) {
  const uint8_t cmd = 0x9F;
  return isp_transact(&cmd, 1, id, 3);
}

static void print_err(const char *code, const char *detail) {
  Serial.printf("ERR %s %s\n", code, detail);
}

// Shared SERDB transaction helper (one I2C transaction, D-prefixed diagnostics)
static bool serdb_tx(const char *prefix, const char *tag, const uint8_t *data, size_t n) {
  I2cTxResult r = i2c_write_diag(data, n, SERDB_ADDR);
  Serial.printf("D %s tx=%s rc=%u queued=%u\n", prefix, tag, r.rc, (unsigned)r.queued);
  return r.rc == 0 && r.queued == n;
}

static bool serdb_setup(const char *prefix, const uint8_t *chsel = serdb_ch3_setup) {
  const uint8_t sync[5] = {'S', 'E', 'R', 'D', 'B'};
  const uint8_t c53 = 0x53, c7f = 0x7F, c35 = 0x35, c71 = 0x71;
  if (!serdb_tx(prefix, "sync", sync, sizeof(sync))) return false;
  if (!serdb_tx(prefix, "chsel0", &chsel[0], 1)) return false;
  if (!serdb_tx(prefix, "chsel1", &chsel[1], 1)) return false;
  if (!serdb_tx(prefix, "chsel2", &chsel[2], 1)) return false;
  if (!serdb_tx(prefix, "cmd53", &c53, 1)) return false;
  if (!serdb_tx(prefix, "cmd7F", &c7f, 1)) return false;
  if (!serdb_tx(prefix, "cmd35", &c35, 1)) return false;
  if (!serdb_tx(prefix, "cmd71", &c71, 1)) return false;
  return true;
}

static void serdb_cleanup(const char *prefix) {
  // Cleanup always attempted; results recorded separately, 0x45's NACK is expected.
  const uint8_t c34 = 0x34, c45 = 0x45;
  I2cTxResult d = i2c_write_diag(&c34, 1, SERDB_ADDR);
  Serial.printf("D %s tx=disable34 rc=%u queued=%u\n", prefix, d.rc, (unsigned)d.queued);
  I2cTxResult e = i2c_write_diag(&c45, 1, SERDB_ADDR);
  Serial.printf("D %s tx=exit45 rc=%u queued=%u (documented NACK expected)\n",
                prefix, e.rc, (unsigned)e.queued);
}

static bool serdb_read1(const char *prefix, uint8_t *reg) {
  size_t got = Wire.requestFrom((uint8_t)SERDB_ADDR, (uint8_t)1, (uint8_t)true);
  if (got == 1 && Wire.available() >= 1) {
    *reg = (uint8_t)Wire.read();
    Serial.printf("D %s read_got=1 reg=0x%02X\n", prefix, *reg);
    return true;
  }
  Serial.printf("D %s read_got=%u reg=invalid\n", prefix, (unsigned)got);
  return false;
}

static bool serdb_read_addr(const char *prefix, uint32_t addr, uint8_t *reg) {
  uint8_t a[5] = {0x10, (uint8_t)(addr >> 24), (uint8_t)(addr >> 16),
                  (uint8_t)(addr >> 8), (uint8_t)addr};
  Serial.printf("D %s addr=0x%08lX\n", prefix, (unsigned long)addr);
  if (!serdb_tx(prefix, "reg-addr", a, sizeof(a))) return false;
  return serdb_read1(prefix, reg);
}

// SERDB REG_CHIP_VERSION probe (read-only): activation + channel 3 + exactly
// one address, exactly one byte (the low lane SERDB returns; the register is
// 16 bits). No MCU stop/resume, no register writes, no other addresses.
static void handle_serdb_version(void) {
  bool ok = serdb_setup("serdb_version");
  uint8_t reg = 0xFF;
  if (ok) ok = serdb_read_addr("serdb_version", 0x00001ECE, &reg);
  serdb_cleanup("serdb_version");
  if (ok) Serial.printf("SERDBVERSION OK reg=0x%02X\n", reg);
  else print_err("i2c", "serdb-version");
}

// SERDB register-read probe (read-only): activation + channel 3 + one register.
// No MCU stop/resume, no register writes, no other addresses.
static void handle_serdb_probe(void) {
  bool ok = serdb_setup("serdb_probe");
  uint8_t reg = 0xFF;
  if (ok) ok = serdb_read_addr("serdb_probe", 0x00001ECF, &reg);
  serdb_cleanup("serdb_probe");
  if (ok) Serial.printf("SERDBPROBE OK reg=0x%02X\n", reg);
  else print_err("i2c", "serdb-probe");
}

// SERDB multi-register trace (read-only): the three documented addresses, in
// the published order. Values are reported; a mismatch with the reference is
// NOT a failure. Aborts mid-sequence on transaction/read failure; cleanup is
// always attempted.
static void handle_serdb_trace(void) {
  static const uint32_t addrs[3] = {0x00001ECF, 0x00001ECC, 0x00001ECD};
  static const uint8_t refs[3] = {0x00, 0xF5, 0x00};
  bool ok = serdb_setup("serdb_trace");
  uint8_t vals[3] = {0xFF, 0xFF, 0xFF};
  for (int i = 0; ok && i < 3; i++) {
    if (!serdb_read_addr("serdb_trace", addrs[i], &vals[i])) ok = false;
    else Serial.printf("D serdb_trace addr=0x%08lX reg=0x%02X ref=0x%02X match=%s\n",
                       (unsigned long)addrs[i], vals[i], refs[i],
                       vals[i] == refs[i] ? "yes" : "no");
  }
  serdb_cleanup("serdb_trace");
  if (ok) Serial.printf("SERDBTRACE OK reg0=0x%02X reg1=0x%02X reg2=0x%02X\n", vals[0], vals[1], vals[2]);
  else print_err("i2c", "serdb-trace");
}

// SERDB bulk read of the compiled-in allowlist (read-only): activation +
// channel selects from the generated header + one 1-byte read per entry, then
// standard cleanup. Per-entry read failures are reported as E lines and don't
// abort the session (each entry is independent). No writes, no MCU stop/resume.
static void handle_serdb_dump(uint8_t ch) {
  if (ch != 3 && ch != 4) { print_err("arg", "SERDBDUMP 3|4"); return; }
  const SerdbAllowEntry *list = (ch == 3) ? serdb_ch3_list : serdb_ch4_list;
  const uint8_t count = (ch == 3) ? SERDB_CH3_COUNT : SERDB_CH4_COUNT;
  const uint8_t *chsel = (ch == 3) ? serdb_ch3_setup : serdb_ch4_setup;

  bool ok = serdb_setup("serdb_dump", chsel);
  bool session_ok = ok;
  uint8_t okc = 0, failc = 0;
  for (uint8_t i = 0; session_ok && i < count; i++) {
    uint8_t reg;
    if (serdb_read_addr("serdb_dump", list[i].addr, &reg)) {
      Serial.printf("R %04X %s 0x%02X\n", list[i].addr, list[i].name, reg);
      okc++;
    } else {
      Serial.printf("E %04X %s\n", list[i].addr, list[i].name);
      failc++;
    }
  }
  serdb_cleanup("serdb_dump");
  if (session_ok) {
    Serial.printf("SERDBDUMP OK ch=%u ok=%u fail=%u\n", ch, okc, failc);
  } else {
    print_err("i2c", "serdb-dump: setup failed, no reads issued");
  }
}

static void handle_id(void) {
  if (!isp_enter()) { print_err("i2c", "enter-isp"); return; }
  uint8_t id[3] = {0, 0, 0};
  if (!isp_jedec(id)) { print_err("i2c", "jedec"); return; }
  Serial.printf("JEDEC %02X%02X%02X\n", id[0], id[1], id[2]);
}

static void handle_scan(void) {
  for (uint16_t a = 0x03; a < 0x78; a++) {
    Wire.beginTransmission((uint8_t)a);
    if (Wire.endTransmission() == 0) Serial.printf("FOUND 0x%02X\n", a);
  }
  Serial.println("DONE");
}

static void handle_read(uint32_t offset, uint32_t length) {
  if ((uint64_t)offset + length > FLASH_BYTES) { print_err("range", "beyond-16MiB"); return; }
  if (length == 0) { print_err("range", "zero-length"); return; }
  if (!isp_enter()) { print_err("i2c", "enter-isp"); return; }

  Serial.printf("DATA %08lX\n", (unsigned long)length);

  uint32_t remaining = length;
  uint32_t addr = offset;
  uint32_t crc = 0xFFFFFFFFUL;
  uint8_t buf[SPI_CHUNK];

  while (remaining) {
    size_t n = remaining < SPI_CHUNK ? remaining : SPI_CHUNK;
    if (!isp_read_retry(addr, buf, n)) {
      // Session stays active; the host will send EXIT and clean up.
      print_err("i2c", "read-failed");
      return;
    }
    crc = crc32_update(crc, buf, n);
    Serial.write(buf, n);
    addr += n;
    remaining -= n;
  }

  crc ^= 0xFFFFFFFFUL;
  Serial.printf("SUM32 %08lX\nEND\n", (unsigned long)crc);
}

static void handle_line(char *line) {
  char *save = NULL;
  char *cmd = strtok_r(line, " ", &save);
  if (!cmd) return;

  if (!strcmp(cmd, "PING")) { Serial.println("PONG"); return; }
  if (!strcmp(cmd, "INFO")) { Serial.println("INFO msp-isp-reader fw=1 mode=READ-ONLY"); return; }
  if (!strcmp(cmd, "SYNC")) { Serial.println(isp_enter() ? "OK" : "ERR i2c sync"); return; }
  if (!strcmp(cmd, "SERDBSYNC")) { Serial.println(serdb_sync() ? "SERDB OK" : "ERR i2c serdb"); return; }
  if (!strcmp(cmd, "SERDBVERSION")) { handle_serdb_version(); return; }
  if (!strcmp(cmd, "SERDBPROBE")) { handle_serdb_probe(); return; }
  if (!strcmp(cmd, "SERDBTRACE")) { handle_serdb_trace(); return; }
  if (!strcmp(cmd, "SERDBDUMP")) {
    char *a_ch = strtok_r(NULL, " ", &save);
    if (a_ch && (a_ch[0] == '3' || a_ch[0] == '4') && a_ch[1] == '\0') {
      handle_serdb_dump((uint8_t)(a_ch[0] - '0'));
    } else {
      print_err("args", "SERDBDUMP <3|4>");
    }
    return;
  }
  if (!strcmp(cmd, "ID"))   { handle_id(); return; }
  if (!strcmp(cmd, "SCAN")) { handle_scan(); return; }
  if (!strcmp(cmd, "EXIT")) { Serial.println(isp_exit() ? "BYE" : "ERR i2c exit"); return; }
  if (!strcmp(cmd, "READ")) {
    char *a_off = strtok_r(NULL, " ", &save);
    char *a_len = strtok_r(NULL, " ", &save);
    if (!a_off || !a_len) { print_err("args", "READ <off_hex> <len_hex>"); return; }
    uint32_t offset = strtoul(a_off, NULL, 16);
    uint32_t length = strtoul(a_len, NULL, 16);
    handle_read(offset, length);
    return;
  }
  Serial.printf("ERR unknown %s\n", cmd);
}

void setup() {
  Serial.begin(HOST_BAUD);
  Serial.setTimeout(1000);
  crc32_init();
  Wire.setBufferSize(264);
  Wire.begin(SDA_PIN, SCL_PIN, I2C_CLOCK_HZ);
  Wire.setTimeOut(50);
  delay(50);
  Serial.println("READY msp-isp-reader fw=1");
}

void loop() {
  static char line[96];
  static size_t len = 0;
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\r') continue;
    if (c == '\n') {
      line[len] = '\0';
      len = 0;
      if (line[0]) handle_line(line);
    } else if (len + 1 < sizeof(line)) {
      line[len++] = c;
    } else {
      len = 0; // overflow: drop line
    }
  }
  delay(1);
}
