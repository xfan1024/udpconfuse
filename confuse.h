#ifndef __confuse_h__
#define __confuse_h__

#define DEFAULT_SRAND_VAL 8675728858075378228ull

void confuse_data(uint8_t *data, unsigned int len, uint64_t srand);

#endif