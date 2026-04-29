/*
 * Hardware True Random Number Generator for SAM3X8E (Arduino Due)
 *
 * Two entropy sources, mixed and health-tested in firmware:
 *   1. On-chip SAM3X8E TRNG peripheral (ring-oscillator-based per Atmel datasheet)
 *   2. Software ring-oscillator emulation via timer jitter sampling
 *
 * Output: raw bytes over USB serial at 115200 baud, framed as:
 *   [0xAA 0x55] <byte> <crc8>     repeated
 *
 * NIST SP 800-90B continuous health tests (RCT + APT) run inline.
 * On health-test failure, firmware emits 0xFF 0xFF and halts output until reset.
 *
 * Author: Usama Mustafa
 * License: MIT
 */

#include <Arduino.h>

// SAM3X8E TRNG register definitions (from atmel SAM3X datasheet, ch. 39)
#define TRNG_BASE         0x400BC000u
#define TRNG_CR           (*(volatile uint32_t*)(TRNG_BASE + 0x00))
#define TRNG_IER          (*(volatile uint32_t*)(TRNG_BASE + 0x10))
#define TRNG_IDR          (*(volatile uint32_t*)(TRNG_BASE + 0x14))
#define TRNG_ISR          (*(volatile uint32_t*)(TRNG_BASE + 0x1C))
#define TRNG_ODATA        (*(volatile uint32_t*)(TRNG_BASE + 0x50))
#define TRNG_KEY          0x524E4700u  /* "RNG" */

// Power Management Controller — TRNG peripheral ID = 41
#define PMC_PCER1         (*(volatile uint32_t*)0x400E0700u)
#define TRNG_PID_BIT      (1u << (41 - 32))

// NIST SP 800-90B continuous health tests
// Repetition Count Test (RCT): assume H_min = 0.5 bits/byte (conservative);
// cutoff C = 1 + ceil(20 / H_min) = 41
static const uint16_t RCT_CUTOFF = 41;
// Adaptive Proportion Test (APT): window W = 512, H_min = 0.5,
// cutoff = critbinom(W, 2^-H_min, 1 - 2^-20) ~= 410 for W=512
static const uint16_t APT_WINDOW = 512;
static const uint16_t APT_CUTOFF = 410;

static uint8_t   rct_last_value   = 0;
static uint16_t  rct_run_count    = 0;
static uint8_t   apt_reference    = 0;
static uint16_t  apt_match_count  = 0;
static uint16_t  apt_window_pos   = 0;
static bool      health_ok        = true;

static inline uint8_t crc8(uint8_t b) {
  uint8_t c = b;
  for (uint8_t i = 0; i < 8; ++i) c = (c & 0x80) ? (uint8_t)((c << 1) ^ 0x07) : (uint8_t)(c << 1);
  return c;
}

static void trng_peripheral_init() {
  PMC_PCER1 = TRNG_PID_BIT;     // enable peripheral clock
  TRNG_CR = TRNG_KEY | 0x1u;    // enable TRNG with security key
  TRNG_IDR = 0x1u;              // disable interrupt; we poll
}

static uint32_t trng_read_word() {
  while ((TRNG_ISR & 0x1u) == 0) { /* wait for DATRDY */ }
  return TRNG_ODATA;
}

/*
 * Software ring-oscillator emulation:
 * Sample the SAM3X8E system tick (84 MHz) on a tight loop where the loop
 * timing is gated by a side-effect-laden floating-point operation. The jitter
 * between SysTick reads forms the entropy source. XOR'd with the on-chip TRNG
 * to defend against any single-source compromise.
 */
static uint8_t ring_jitter_byte() {
  uint8_t b = 0;
  for (uint8_t i = 0; i < 8; ++i) {
    volatile float x = micros() * 1.0001f;
    x = x * x;
    uint32_t t1 = SysTick->VAL;
    asm volatile ("nop; nop; nop; nop; nop; nop;");
    uint32_t t2 = SysTick->VAL;
    b = (uint8_t)((b << 1) | ((t1 ^ t2 ^ (uint32_t)(x * 1e6f)) & 0x1u));
  }
  return b;
}

static bool health_update(uint8_t v) {
  // RCT
  if (v == rct_last_value) {
    if (++rct_run_count >= RCT_CUTOFF) return false;
  } else {
    rct_last_value = v;
    rct_run_count = 1;
  }
  // APT
  if (apt_window_pos == 0) {
    apt_reference = v;
    apt_match_count = 1;
  } else {
    if (v == apt_reference) ++apt_match_count;
  }
  if (++apt_window_pos >= APT_WINDOW) {
    if (apt_match_count >= APT_CUTOFF) return false;
    apt_window_pos = 0;
  }
  return true;
}

void setup() {
  Serial.begin(115200);
  while (!Serial) { /* wait for USB CDC */ }
  trng_peripheral_init();
  delay(50);   // power-on stabilisation
  Serial.println("# kyber-trng-entropy-injection :: TRNG online (SAM3X8E)");
}

void loop() {
  if (!health_ok) {
    // Hard-fail beacon — firmware refuses to emit further entropy
    Serial.write(0xFF); Serial.write(0xFF);
    delay(1000);
    return;
  }

  uint32_t w = trng_read_word();
  for (int shift = 0; shift < 32; shift += 8) {
    uint8_t hw = (uint8_t)((w >> shift) & 0xFFu);
    uint8_t sw = ring_jitter_byte();
    uint8_t mixed = hw ^ sw;       // dual-source XOR mix

    if (!health_update(mixed)) {
      health_ok = false;
      return;
    }

    Serial.write(0xAA); Serial.write(0x55);
    Serial.write(mixed);
    Serial.write(crc8(mixed));
  }
}
