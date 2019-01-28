#include <stdio.h>
#include <string.h>
#include "cpucycles.h"
#include "speed.h"
#include "../params.h"
#include "../sign.h"

#define MLEN 500
#define NTESTS 5000


#define TEST_JSON_PLAINTEXT "{\n" \
"		body: {\n" \
"				\"from\": \"pub_key_generated_by_library_in_testing_1\",\n" \
"				\"to\": \"pub_key_generated_by_library_in_testing_2\",\n" \
"				\"amount\": 3,1415,\n" \
"				\"itemHash\": \"bdad5ccb7a52387f5693eaef54aeee6de73a6ada7acda6d93a665abbdf954094\"\n" \
"				\"seed\": \"2953135335240383704\"\n" \
"		},\n" \
"		\"fee\": 0,7182,\n" \
"		\"network_id\": 7,\n" \
"		\"protocol_version\": 0,\n" \
"		\"service_id\": 5,\n" \
"}"

unsigned long long timing_overhead;

int main(void)
{
	unsigned int i;
	int ret;
	unsigned long long j, mlen, smlen;
	unsigned char m[MLEN];
	unsigned char sm[MLEN + CRYPTO_BYTES];
	unsigned char m2[MLEN + CRYPTO_BYTES];
	unsigned char pk[CRYPTO_PUBLICKEYBYTES];
	unsigned char sk[CRYPTO_SECRETKEYBYTES];
	unsigned long long tkeygen[NTESTS], tsign[NTESTS], tverify[NTESTS];
	unsigned long long totalLength = 0;

	snprintf((char*)m, MLEN, "%s", TEST_JSON_PLAINTEXT);
	printf("Original String:\n%s\nlength: %lu\n", (char*)m, strlen((char*)m) + 1);
	printf("\n");
	timing_overhead = cpucycles_overhead();

	for(i = 0; i < NTESTS; ++i) {
		// start to prepare to generate keypair
		tkeygen[i] = cpucycles_start();
		crypto_sign_keypair(pk, sk);
		tkeygen[i] = cpucycles_stop() - tkeygen[i] - timing_overhead;

		// start to encrypt
		tsign[i] = cpucycles_start();
		crypto_sign(sm, &smlen, m, strlen((char*)m) + 1, sk);
		tsign[i] = cpucycles_stop() - tsign[i] - timing_overhead;

		// start to decrpt
		tverify[i] = cpucycles_start();
		ret = crypto_sign_open(m2, &mlen, sm, smlen, pk);
		tverify[i] = cpucycles_stop() - tverify[i] - timing_overhead;

		if(ret) {
			printf("Verification failed\n");
			return -1;
		}

		if(mlen != (strlen((char*)m) + 1)) {
			printf("Message lengths don't match\n");
			return -1;
		}
		totalLength += smlen;

		for(j = 0; j < mlen; ++j) {
			if(m[j] != m2[j]) {
				printf("Messages don't match\n");
				return -1;
			}
		}
	}

	print_results("keygen:", tkeygen, NTESTS);
	print_results("sign: ", tsign, NTESTS);
	print_results("verify: ", tverify, NTESTS);
	printf("average length: %llu\n", (totalLength / NTESTS));


	return 0;
}
