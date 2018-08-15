#include <stdio.h> 
#include <stdint.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>


void *load_key(const uint8_t *pem_key, uint32_t len)
{
		EVP_PKEY *pkey = NULL;
		BIO *key = NULL;

		do
		{
				key = BIO_new_mem_buf((void *)pem_key, len);
				if(key == NULL) printf( "BIO_new_mem_buf error");

				pkey = PEM_read_bio_PrivateKey(key, NULL, (pem_password_cb *)NULL, NULL);
				if(pkey == NULL) printf( "PEM_read_bio_PrivateKey error");
		} while (0);

		if (key != NULL)
		{
				BIO_free(key);
		}

		return pkey;
}

int main()
{
		const unsigned char pkey_data[] = { 
#include "pri_hex.pem"
};
		EVP_PKEY *pkey ;

		pkey = (EVP_PKEY *)load_key(pkey_data, pkey_data_size);

		RSA_print_fp(stdout, pkey->pkey.rsa, 0);
		if(pkey)
		{
				EVP_PKEY_free(pkey);
		}

		return 0;
}
