#include "hal.h"
#include <stdint.h>
#include <stdlib.h>
#include "simpleserial.h"
#include "api.h"
#include "ascon.h"
#include "crypto_aead.h"
#include "permutations.h"
#include "printstate.h"
#include "word.h"

int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
                        const unsigned char* m, unsigned long long mlen,
                        const unsigned char* ad, unsigned long long adlen,
                        const unsigned char* nsec, const unsigned char* npub,
                        const unsigned char* k) {
   trigger_high();
  (void)nsec;

  /* set ciphertext size */
  *clen = mlen + CRYPTO_ABYTES;

  /* load key and nonce */
  const uint64_t K0 = LOADBYTES(k + 0, 4) >> 32;
  const uint64_t K1 = LOADBYTES(k + 4, 8);
  const uint64_t K2 = LOADBYTES(k + 12, 8);
  const uint64_t N0 = LOADBYTES(npub, 8);
  const uint64_t N1 = LOADBYTES(npub + 8, 8);

  /* initialize */
  ascon_state_t s;
  s.x[0] = ASCON_80PQ_IV | K0;
  s.x[1] = K1;
  s.x[2] = K2;
  s.x[3] = N0;
  s.x[4] = N1;
  printstate("init 1st key xor", &s);
  P12(&s);
  s.x[2] ^= K0;
  s.x[3] ^= K1;
  s.x[4] ^= K2;
  printstate("init 2nd key xor", &s);

  if (adlen) {
    /* full associated data blocks */
    while (adlen >= ASCON_128_RATE) {
      s.x[0] ^= LOADBYTES(ad, 8);
      printstate("absorb adata", &s);
      P6(&s);
      ad += ASCON_128_RATE;
      adlen -= ASCON_128_RATE;
    }
    /* final associated data block */
    s.x[0] ^= LOADBYTES(ad, adlen);
    s.x[0] ^= PAD(adlen);
    printstate("pad adata", &s);
    P6(&s);
  }
  /* domain separation */
  s.x[4] ^= 1;
  printstate("domain separation", &s);

  /* full plaintext blocks */
  while (mlen >= ASCON_128_RATE) {
    s.x[0] ^= LOADBYTES(m, 8);
    STOREBYTES(c, s.x[0], 8);
    printstate("absorb plaintext", &s);
    P6(&s);
    m += ASCON_128_RATE;
    c += ASCON_128_RATE;
    mlen -= ASCON_128_RATE;
  }
  /* final plaintext block */
  s.x[0] ^= LOADBYTES(m, mlen);
  STOREBYTES(c, s.x[0], mlen);
  s.x[0] ^= PAD(mlen);
  c += mlen;
  printstate("pad plaintext", &s);

  /* finalize */
  s.x[1] ^= K0 << 32 | K1 >> 32;
  s.x[2] ^= K1 << 32 | K2 >> 32;
  s.x[3] ^= K2 << 32;
  printstate("final 1st key xor", &s);
  P12(&s);
  s.x[3] ^= K1;
  s.x[4] ^= K2;
  printstate("final 2nd key xor", &s);

  /* set tag */
  STOREBYTES(c, s.x[3], 8);
  STOREBYTES(c + 8, s.x[4], 8);

  return 0;
  trigger_low();
}

int crypto_aead_decrypt(unsigned char* m, unsigned long long* mlen,
                        unsigned char* nsec, const unsigned char* c,
                        unsigned long long clen, const unsigned char* ad,
                        unsigned long long adlen, const unsigned char* npub,
                        const unsigned char* k) {
  trigger_high();
  (void)nsec;

  if (clen < CRYPTO_ABYTES) return -1;

  /* set plaintext size */
  *mlen = clen - CRYPTO_ABYTES;

  /* load key and nonce */
  const uint64_t K0 = LOADBYTES(k + 0, 4) >> 32;
  const uint64_t K1 = LOADBYTES(k + 4, 8);
  const uint64_t K2 = LOADBYTES(k + 12, 8);
  const uint64_t N0 = LOADBYTES(npub, 8);
  const uint64_t N1 = LOADBYTES(npub + 8, 8);

  /* initialize */
  ascon_state_t s;
  s.x[0] = ASCON_80PQ_IV | K0;
  s.x[1] = K1;
  s.x[2] = K2;
  s.x[3] = N0;
  s.x[4] = N1;
  printstate("init 1st key xor", &s);
  P12(&s);
  s.x[2] ^= K0;
  s.x[3] ^= K1;
  s.x[4] ^= K2;
  printstate("init 2nd key xor", &s);

  if (adlen) {
    /* full associated data blocks */
    while (adlen >= ASCON_128_RATE) {
      s.x[0] ^= LOADBYTES(ad, 8);
      printstate("absorb adata", &s);
      P6(&s);
      ad += ASCON_128_RATE;
      adlen -= ASCON_128_RATE;
    }
    /* final associated data block */
    s.x[0] ^= LOADBYTES(ad, adlen);
    s.x[0] ^= PAD(adlen);
    printstate("pad adata", &s);
    P6(&s);
  }
  /* domain separation */
  s.x[4] ^= 1;
  printstate("domain separation", &s);

  /* full ciphertext blocks */
  clen -= CRYPTO_ABYTES;
  while (clen >= ASCON_128_RATE) {
    uint64_t c0 = LOADBYTES(c, 8);
    STOREBYTES(m, s.x[0] ^ c0, 8);
    s.x[0] = c0;
    printstate("insert ciphertext", &s);
    P6(&s);
    m += ASCON_128_RATE;
    c += ASCON_128_RATE;
    clen -= ASCON_128_RATE;
  }
  /* final ciphertext block */
  uint64_t c0 = LOADBYTES(c, clen);
  STOREBYTES(m, s.x[0] ^ c0, clen);
  s.x[0] = CLEARBYTES(s.x[0], clen);
  s.x[0] |= c0;
  s.x[0] ^= PAD(clen);
  c += clen;
  printstate("pad ciphertext", &s);

  /* finalize */
  s.x[1] ^= K0 << 32 | K1 >> 32;
  s.x[2] ^= K1 << 32 | K2 >> 32;
  s.x[3] ^= K2 << 32;
  printstate("final 1st key xor", &s);
  P12(&s);
  s.x[3] ^= K1;
  s.x[4] ^= K2;
  printstate("final 2nd key xor", &s);

  /* set tag */
  uint8_t t[16];
  STOREBYTES(t, s.x[3], 8);
  STOREBYTES(t + 8, s.x[4], 8);

  /* verify tag (should be constant time, check compiler output) */
  int i;
  int result = 0;
  for (i = 0; i < CRYPTO_ABYTES; ++i) result |= c[i] ^ t[i];
  result = (((result - 1) >> 8) & 1) - 1;

  return result;
  trigger_low();
}




uint8_t get_encrypt(uint8_t* pt, uint8_t len) {
     // Define buffer for ciphertext; size might need to be adjusted depending on the maximum expected length
    unsigned char c[32];
    // Define and initialize variables for encryption
    unsigned long long clen;
    const unsigned char* ad = NULL;
    unsigned long long adlen = 0;
    const unsigned char* nsec = NULL; 
    const unsigned char* npub = "aaa";
    const unsigned char* k = "aaa"; 
  
    crypto_aead_encrypt(c, &clen, pt, len, ad, adlen, nsec, npub, k);
    simpleserial_put('r', 16, c); // Ensure to adjust based on your implementation
    
    return 0x00; // Indicate success
}

uint8_t get_decrypt(uint8_t* c, uint8_t len) {
     // Define buffer for ciphertext; size might need to be adjusted depending on the maximum expected length
    unsigned char m[32];
    // Define and initialize variables for decryption
    unsigned long long mlen;
    const unsigned char* ad = NULL; // Assuming no additional authenticated data
    unsigned long long adlen = 0; // Length of the additional data is 0
    const unsigned char* nsec = NULL; 
    const unsigned char* npub = "aaa"; 
    const unsigned char* k = "aaa"; 
  
    crypto_aead_decrypt(m, &mlen, nsec, c, len, ad, adlen, npub, k);
    simpleserial_put('r', 16, m); 
    
    return 0x00; // Indicate success
}
uint8_t get_key(uint8_t* k, uint8_t len) {
//     
     return 0x00; // Indicate success
}
uint8_t reset(uint8_t* x, uint8_t len) {
    
    if (x != NULL && len > 0) {
        volatile uint8_t *p = x;
        while (len--) *p++ = 0;
    }
    return 0x00; // Indicate success
}

//  Ascon-80pq main function

int main(void) {
    platform_init();
    init_uart();
    trigger_setup();

    simpleserial_init();
#if SS_VER != SS_VER_2_1
    simpleserial_addcmd('p', 16, get_encrypt);
    simpleserial_addcmd('k', 20,get_key);
    simpleserial_addcmd('x', 16, get_decrypt);
#endif
    while(1)
        simpleserial_get();
}


// // Second code

// #include "hal.h"
// #include <stdint.h>
// #include <stdlib.h>
// #include "simpleserial.h"
// #include "api.h"
// #include "ascon.h"
// #include "crypto_aead.h"
// #include "permutations.h"
// #include "printstate.h"
// #include "word.h"





// int crypto_aead_encrypt_decrypt(unsigned char* out, unsigned long long* outlen,
//                                 const unsigned char* in, unsigned long long inlen,
//                                 const unsigned char* ad, unsigned long long adlen,
//                                 const unsigned char* npub, const unsigned char* k, int encrypt);


// int crypto_aead_encrypt_decrypt(unsigned char* out, unsigned long long* outlen,
//                                 const unsigned char* in, unsigned long long inlen,
//                                 const unsigned char* ad, unsigned long long adlen,
//                                 const unsigned char* npub, const unsigned char* k, int encrypt) {
//      trigger_high();
//     (void)outlen; 

//     /* Initialize variables */
//     ascon_state_t s;
//     uint64_t K0, K1, K2, N0, N1;
//     K0 = LOADBYTES(k + 0, 4) >> 32;
//     K1 = LOADBYTES(k + 4, 8);
//     K2 = LOADBYTES(k + 12, 8);
//     N0 = LOADBYTES(npub, 8);
//     N1 = LOADBYTES(npub + 8, 8);

//     s.x[0] = ASCON_80PQ_IV | K0;
//     s.x[1] = K1;
//     s.x[2] = K2;
//     s.x[3] = N0;
//     s.x[4] = N1;

//     P12(&s);
//     s.x[2] ^= K0;
//     s.x[3] ^= K1;
//     s.x[4] ^= K2;

//     /* Process associated data */
//     if (adlen) {
//         while (adlen >= ASCON_128_RATE) {
//             s.x[0] ^= LOADBYTES(ad, 8);
//             P6(&s);
//             ad += ASCON_128_RATE;
//             adlen -= ASCON_128_RATE;
//         }
//         s.x[0] ^= LOADBYTES(ad, adlen);
//         s.x[0] ^= PAD(adlen);
//         P6(&s);
//     }
//     s.x[4] ^= 1; // Domain separation

//     if (encrypt) {
//         /* Encryption */
//         *outlen = inlen + CRYPTO_ABYTES; // Set output length
//         while (inlen >= ASCON_128_RATE) {
//             s.x[0] ^= LOADBYTES(in, 8);
//             STOREBYTES(out, s.x[0], 8);
//             P6(&s);
//             in += ASCON_128_RATE;
//             out += ASCON_128_RATE;
//             inlen -= ASCON_128_RATE;
//         }
//         s.x[0] ^= LOADBYTES(in, inlen);
//         STOREBYTES(out, s.x[0], inlen);
//         s.x[0] ^= PAD(inlen);
//         out += inlen;
//     } else {
//         /* Decryption */
//         if (*outlen < CRYPTO_ABYTES) return -1; // Check output buffer
//         *outlen = inlen - CRYPTO_ABYTES; // Adjust for tag
//         inlen -= CRYPTO_ABYTES; // Exclude tag from inlen
//         while (inlen >= ASCON_128_RATE) {
//             uint64_t c0 = LOADBYTES(in, 8);
//             STOREBYTES(out, s.x[0] ^ c0, 8);
//             s.x[0] = c0;
//             P6(&s);
//             in += ASCON_128_RATE;
//             out += ASCON_128_RATE;
//             inlen -= ASCON_128_RATE;
//         }
//         uint64_t c0 = LOADBYTES(in, inlen);
//         STOREBYTES(out, s.x[0] ^ c0, inlen);
//         s.x[0] = CLEARBYTES(s.x[0], inlen) | c0;
//         s.x[0] ^= PAD(inlen);
//         in += inlen;
//     }

//     /* Finalize */
//     s.x[1] ^= K0 << 32 | K1 >> 32;
//     s.x[2] ^= K1 << 32 | K2 >> 32;
//     s.x[3] ^= K2 << 32;
//     P12(&s);

//     if (encrypt) {
//         s.x[3] ^= K1;
//         s.x[4] ^= K2;
//         STOREBYTES(out, s.x[3], 8);
//         STOREBYTES(out + 8, s.x[4], 8);
//     } else {
//         // Verify tag for decryption
//         uint8_t t[16];
//         STOREBYTES(t, s.x[3], 8);
//         STOREBYTES(t + 8, s.x[4], 8);
//         int result = 0;
//         for (int i = 0; i < CRYPTO_ABYTES; ++i) {
//             result |= in[i] ^ t[i];
//         }
//         result = (((result - 1) >> 8) & 1) - 1;
//         return result;
//     }

//     trigger_low();
//     return 0;
// }

// uint8_t process_input(uint8_t* data, uint8_t len, int encrypt) {
//     static const unsigned char npub[] = "aaa"; 
//     static const unsigned char k[] = "aaa"; 
//     unsigned char output[32]; 
//     unsigned long long output_len;

//     crypto_aead_encrypt_decrypt(output, &output_len, data, len, NULL, 0, npub, k, encrypt);
//     simpleserial_put(encrypt ? 'r' : 's', 16, output);
    
//     return 0x00; // Success
// }

// static inline uint8_t get_encrypt(uint8_t* pt, uint8_t len) {
//     return process_input(pt, len, 1); // Inline for efficiency
// }

// static inline uint8_t get_decrypt(uint8_t* c, uint8_t len) {
//     return process_input(c, len, 0); // Inline for efficiency
// }

// int main(void) {
//     platform_init();
//     init_uart();
//     trigger_setup();

//     simpleserial_init();
//     simpleserial_addcmd('p', 16, get_encrypt);
//     simpleserial_addcmd('x', 16, get_decrypt);
    
//     while(1) simpleserial_get();
// }
