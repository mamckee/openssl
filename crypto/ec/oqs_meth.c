/* OQS authentication methods.
 *
 * This file mimics ecx_meth.c. Compare the oqs* with the ecx* functions
 * to understand the code.
 *
 * TODO:
 *  - Improve error reporting. Define OQS specific error codes, using util/mkerr.pl?
 *    (or perhaps re-use EC_* values?
 *  - Add tests
 *  - FIXMEOQS: which RSA NID should I use in hybrid sig? NID_rsaencryption is used by "req" when using "rsa"?
 */

/* OQS note:
   In addition to post-quantum (PQ) signatures; we also support classical/PQ hybrids. In that case, a classical and a PQ signature
   are generated on the same data, and the resulting signatures are concatenated; the classical and PQ keys are also concatenated
   when serialized. The signed data is first hashed using the SHA-2 hash function matching the security level of the OQS scheme
   (SHA256 for L1, SHA384 for L2/L3, SHA512 for L4/L5) before being signed by the classical algorithm (which can't support
   arbitrarily long messages), and is passed directly to the OQS signature API. The hybrid scheme is identified as a new combo
   scheme with a unique NID. Currently, ECDSA-p256 and RSA3072 hybrids are supported with L1 OQS schemes, and ECDSA-p384 hybrids
   are supported with L3 schemes. The public and private keys are also concatenated when serialized. Encoding of artefacts (keys
   and signatures) are as follow:
   - classical_artefact_length: 4 bytes encoding the size of the classical artefact
   - classical_artefact: the classical artefact of length classical_artefact_length
   - oqs_artefact: the post-quantum artefact, of length determined by the OQS signature context
*/

#include "crypto/evp.h"

#include <oqs/oqs.h>

int oqssl_kem_nids_list[] = {
///// OQS_TEMPLATE_FRAGMENT_LIST_KNOWN_KEM_NIDS_START
        NID_kyber512,
        NID_kyber768,
        NID_kyber1024,
/////// OQS_TEMPLATE_FRAGMENT_LIST_KNOWN_KEM_NIDS_END
};

static int* kem_nid_list = NULL;

int* get_oqssl_kem_nids() {
   if (!kem_nid_list) {
      kem_nid_list = OPENSSL_malloc(sizeof(oqssl_kem_nids_list));
      memcpy(kem_nid_list, oqssl_kem_nids_list, sizeof(oqssl_kem_nids_list));
   }
   return kem_nid_list;
}

/*
 * Maps OpenSSL NIDs to OQS IDs
 */
char* get_oqs_alg_name(int openssl_nid)
{
  switch (openssl_nid)
  {
///// OQS_TEMPLATE_FRAGMENT_ASSIGN_SIG_ALG_START
    case NID_kyber512:
    case NID_p256_kyber512:
      return OQS_KEM_alg_kyber_512;
    case NID_kyber768:
    case NID_p384_kyber768:
      return OQS_KEM_alg_kyber_768;
    case NID_kyber1024:
    case NID_p521_kyber1024:
      return OQS_KEM_alg_kyber_1024;
///// OQS_TEMPLATE_FRAGMENT_ASSIGN_SIG_ALG_END
    default:
      return NULL;
  }
}

/*
 * Returns options when running OQS KEM, e.g., in openssl speed
 */
const char *OQSKEM_options(void)
{
    int offset;
// TODO: Revisit which OQS_COMPILE_FLAGS to show
#ifdef OQS_COMPILE_CFLAGS
    const char* OQSKEMALGS = "OQS KEM build : ";
    char* result =  OPENSSL_zalloc(strlen(OQS_COMPILE_CFLAGS)+OQS_OPENSSL_KEM_algs_length*40); // OK, a bit pessimistic but this will be removed very soon...
    memcpy(result, OQSKEMALGS, offset = strlen(OQSKEMALGS));
    memcpy(result+offset, OQS_COMPILE_CFLAGS, strlen(OQS_COMPILE_CFLAGS));
    offset += strlen(OQS_COMPILE_CFLAGS);
#else
    const char* OQSKEMALGS = "";
    char* result =  OPENSSL_zalloc(OQS_OPENSSL_KEM_algs_length*40); // OK, a bit pessimistic but this will be removed very soon...
    memcpy(result, OQSKEMALGS, offset = strlen(OQSKEMALGS));
#endif

    result[offset++]='-';
    int i;
    for (i=0; i<OQS_OPENSSL_KEM_algs_length;i++) {
       const char* name = OBJ_nid2sn(oqssl_kem_nids_list[i]);
       if (OQS_KEM_alg_is_enabled(get_oqs_alg_name(oqssl_kem_nids_list[i]))) {
           int l = strlen(name);
           memcpy(result+offset, name, l);
           if (i<OQS_OPENSSL_KEM_algs_length-1) {
              result[offset+l]=',';
              offset = offset+l+1;
           }
       }
    }
    return result;
}