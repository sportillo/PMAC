// aes_test.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#define READ_SIZE 64*1024

const char* filename;
const char* key;
unsigned int num_threads;

size_t pmac_bs;
off_t f_size;

unsigned char *zeros, *L, *iL, *tag;

typedef struct {
	unsigned int tid;
	unsigned char *buf_in;
	unsigned char *buf_out;
	long length;
} pmac_struct_t;

int crypt_msg(unsigned char *buf_in,
	unsigned char **buf_out,
	long length,
	const char *secret,
	int do_encrypt);

void *pmac_block_process(void *arg);

#ifdef __APPLE__
double subtractTimes(uint64_t endTime, uint64_t startTime);
#endif

int main(int argc, char* argv[])
{
	pthread_t       *threads;
	pmac_struct_t   *pmac_structs;
    
#ifdef __APPLE__
    uint64_t    begin, end;
#else
    clock_t     begin, end;
#endif
    
	double      elapsed;

	struct stat     st;
	long            f_offset;

	unsigned int i, j;
	unsigned char output[128], *output_enc;

    /* Parse input parameters */
    
	if (argc < 4)
	{
		fprintf(stderr, "Usage: aes_test block_size filename key\n");
		return -1;
	}

	pmac_bs = strtol(argv[1], NULL, 0) << 20;
	filename = argv[2];
	key = argv[3];

    /* Get file size */
    
	if (stat(filename, &st) == 0)
		f_size = st.st_size;
	else
	{
		fprintf(stderr, "Error getting file stats\n");
		return -1;
	}

	num_threads = f_size / pmac_bs;
	num_threads += (f_size % pmac_bs) ? 1 : 0;

	threads = malloc(num_threads * sizeof(pthread_t));
	pmac_structs = malloc(num_threads * sizeof(pmac_struct_t));

	f_offset = 0;

	printf("=== PMAC implementation using RC2 CBC ===\n");
	printf("Filename:\t%s\n", filename);
	printf("File size:\t%lldM\n", f_size >> 20);
	printf("Block size:\t%lluM\n", (unsigned long long) (pmac_bs >> 20));
	printf("Threads:\t%d\n", num_threads);
	printf("=========================================\n");

#ifdef __APPLE__
    begin = mach_absolute_time();
#else
	begin = clock();
#endif
	zeros = malloc(pmac_bs);
	memset(zeros, 0, pmac_bs);

	i = crypt_msg(zeros, &L, pmac_bs, key, 1);
	assert(i >= pmac_bs);

	free(zeros);

	L[pmac_bs - 1] = 1;

	iL = malloc(pmac_bs);
	memset(iL, 0, pmac_bs);

	tag = malloc(pmac_bs);

	FILE *tmp = fopen(filename, "rb");

	for (i = 0; i < num_threads - 1; i++)
	{
		int rc;
		unsigned int j;

		pmac_structs[i].buf_in = malloc(pmac_bs);

		fseek(tmp, f_offset, SEEK_SET);
		fread(pmac_structs[i].buf_in, 1, pmac_bs, tmp);

		if (i > 0)
		for (j = 0; j < pmac_bs; j++)
			iL[j] += L[j];

		for (j = 0; j < pmac_bs; j++)
			pmac_structs[i].buf_in[j] += iL[j];

		pmac_structs[i].tid = i;
		pmac_structs[i].length = pmac_bs;

		f_offset += pmac_bs;

		rc = pthread_create(&threads[i], NULL, pmac_block_process, (void *)&pmac_structs[i]);
		if (rc)
		{
			printf("ERROR; return code from pthread_create() is %d\n", rc);
			return -1;
		}
	}

	for (i = 0; i < num_threads - 1; i++)
	{
		unsigned int j;
		void *tid;

		pthread_join(threads[i], &tid);

		for (j = 0; j < pmac_bs; j++)
			tag[j] += pmac_structs[(int)tid].buf_out[j];
	}

	pmac_structs[num_threads - 1].buf_in = malloc(pmac_bs);
	fread(pmac_structs[num_threads - 1].buf_in, 1, f_size - f_offset, tmp);
	
	if (f_size != f_offset) {
		memset(pmac_structs[num_threads - 1].buf_in + (f_size - f_offset), 0, pmac_bs - (f_size - f_offset));
		pmac_structs[num_threads - 1].buf_in[pmac_bs - 1] = 1;
	}

	for (i = 0; i < pmac_bs; i++)
		tag[i] += pmac_structs[num_threads - 1].buf_in[i];

	free(pmac_structs[num_threads - 1].buf_in);

	i = crypt_msg(tag, &output_enc, pmac_bs, key, 1);

	FILE *out = fopen("pmac.dat", "wb");
    fwrite(output_enc, 1, 128, out);
    fclose(out);
    
#ifdef __APPLE__
    end = mach_absolute_time();
    elapsed = subtractTimes(end, begin);
#else
	end = clock();
	elapsed = (double)(end - begin) / (CLOCKS_PER_SEC);
#endif

	printf("Done in %g seconds.\n", elapsed);

	fclose(tmp);

	for (i = 0; i < num_threads - 1; i++)
		free(pmac_structs[i].buf_out);

	free(L);
	free(iL);
	free(threads);
	free(pmac_structs);
	return 0;
}

void *pmac_block_process(void *arg)
{
	int outlen;
	pmac_struct_t *pmac = (pmac_struct_t *)arg;

	outlen = crypt_msg(pmac->buf_in, &(pmac->buf_out), pmac->length, key, 1);

	free(pmac->buf_in);

	return (void *)pmac->tid;
}

int crypt_msg(unsigned char *buf_in, unsigned char **buf_out, long length, const char *secret, int do_encrypt)
{
	int outlen, tmplen;

	unsigned char iv[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	unsigned char *key = malloc(strlen(secret));
	memcpy((char *)key, secret, strlen(secret));

	*buf_out = malloc(length + EVP_MAX_BLOCK_LENGTH);
	assert(*buf_out != 0);

	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_CipherInit_ex(&ctx, EVP_rc2_cbc(), NULL, NULL, NULL, do_encrypt);
	EVP_CIPHER_CTX_set_key_length(&ctx, strlen(secret));
	EVP_CipherInit_ex(&ctx, NULL, NULL, key, iv, do_encrypt);

	if (!EVP_CipherUpdate(&ctx, *buf_out, &outlen, buf_in, length))
	{
		fprintf(stderr, "EVP_CipherUpdate: crypt_file %d\n", do_encrypt);
		EVP_CIPHER_CTX_cleanup(&ctx);
		return -1;
	}

	if (!EVP_CipherFinal_ex(&ctx, (*buf_out) + outlen, &tmplen))
	{
		fprintf(stderr, "EVP_CipherFinal: crypt_file %d\n", do_encrypt);
		EVP_CIPHER_CTX_cleanup(&ctx);
		return -1;
	}

	outlen += tmplen;

	free(key);
	EVP_CIPHER_CTX_cleanup(&ctx);
	return outlen;
}

#ifdef __APPLE__
double subtractTimes( uint64_t endTime, uint64_t startTime )
{
    uint64_t difference = endTime - startTime;
    static double conversion = 0.0;
    
    if( conversion == 0.0 )
    {
        mach_timebase_info_data_t info;
        kern_return_t err = mach_timebase_info( &info );
        
        //Convert the timebase into seconds
        if( err == 0  )
            conversion = 1e-9 * (double) info.numer / (double) info.denom;
    }
    
    return conversion * (double) difference;
}
#endif
