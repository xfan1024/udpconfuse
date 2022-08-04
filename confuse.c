#include <stdint.h>
#include <endian.h>

#define likely(x)       __builtin_expect((x),1)

static inline uint64_t xorshift_next(uint64_t x64)
{
	x64 ^= x64 << 13;
	x64 ^= x64 >> 7;
	x64 ^= x64 << 17;
	return x64;
}

void confuse_data(uint8_t *data, unsigned int len, uint64_t srand) {
	unsigned int i;
	union {
		uint8_t bytes[8];
		uint64_t val;
	} u;

	while (likely(len >= 8)) {
		srand = xorshift_next(srand);
		u.val = htole64(srand);
		for (i = 0; i < 8; i++) {
			*data++ ^= u.bytes[i];
		}
		len -= 8;
	}
	if (likely(len)) {
		srand = xorshift_next(srand);
		u.val = htole64(srand);
		for (i = 0; i < len; i++) {
			*data++ ^= u.bytes[i];
		}
	}
}
