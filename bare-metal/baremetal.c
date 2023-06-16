#include <stdint.h>
#include <stdbool.h>

#define U8250_RX_TX     *((volatile uint8_t*)(0x10000000))
#define U8250_RX_READY  *((volatile uint8_t*)(0x10000005))

void memcpy(void *dest, const void * src, uint32_t n) {
  uint8_t* d = dest;
  const uint8_t* s = src;
  for (uint32_t i = 0; i < n; i++) {
    d[i] = s[i];
  }
}

void uart_write_string(const char* str) {
  uint32_t i = 0;
  while (1) {
    if (str[i] == '\0') return;
    U8250_RX_TX = str[i++];
  }
}

int main() {
  const char data[] = "Hello from the bare metal!\n";

  uart_write_string(data);
  uart_write_string("> ");
  char uart_data;

  while (1) {
    if (U8250_RX_READY) {
      // Simple echo back
      uart_data = U8250_RX_TX;
      U8250_RX_TX = uart_data;
    }
  }
}
