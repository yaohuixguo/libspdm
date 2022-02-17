/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * PEM (Privacy Enhanced Mail) format Handler Wrapper Implementation.
 **/

#include "internal_crypt_lib.h"
#include <mbedtls/pem.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>

static uintn ascii_str_len(IN const char *string)
{
    uintn length;

    ASSERT(string != NULL);
    if (string == NULL) {
        return 0;
    }

    for (length = 0; *string != '\0'; string++, length++) {
        ;
    }
    return length;
}

/**
 * Retrieve the RSA Private key from the password-protected PEM key data.
 *
 * @param[in]  pem_data      Pointer to the PEM-encoded key data to be retrieved.
 * @param[in]  pem_size      size of the PEM key data in bytes.
 * @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
 * @param[out] rsa_context   Pointer to new-generated RSA context which contain the retrieved
 *                         RSA private key component. Use rsa_free() function to free the
 *                         resource.
 *
 * If pem_data is NULL, then return false.
 * If rsa_context is NULL, then return false.
 *
 * @retval  true   RSA Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 *
 **/
bool rsa_get_private_key_from_pem(IN const uint8_t *pem_data,
                                  IN uintn pem_size,
                                  IN const char *password,
                                  OUT void **rsa_context)
{
    int32_t ret;
    mbedtls_pk_context pk;
    mbedtls_rsa_context *rsa;
    uint8_t *new_pem_data;
    uintn password_len;

    if (pem_data == NULL || rsa_context == NULL || pem_size > INT_MAX) {
        return false;
    }

    new_pem_data = NULL;
    if (pem_data[pem_size - 1] != 0) {
        new_pem_data = allocate_pool(pem_size + 1);
        if (new_pem_data == NULL) {
            return false;
        }
        copy_mem_s(new_pem_data, pem_size + 1, pem_data, pem_size);
        new_pem_data[pem_size] = 0;
        pem_data = new_pem_data;
        pem_size += 1;
    }

    mbedtls_pk_init(&pk);

    if (password != NULL) {
        password_len = ascii_str_len(password);
    } else {
        password_len = 0;
    }

    ret = mbedtls_pk_parse_key(&pk, pem_data, pem_size,
                               (const uint8_t *)password, password_len);

    if (new_pem_data != NULL) {
        free_pool(new_pem_data);
        new_pem_data = NULL;
    }

    if (ret != 0) {
        mbedtls_pk_free(&pk);
        return false;
    }

    if (mbedtls_pk_get_type(&pk) != MBEDTLS_PK_RSA) {
        mbedtls_pk_free(&pk);
        return false;
    }

    rsa = rsa_new();
    if (rsa == NULL) {
        return false;
    }
    ret = mbedtls_rsa_copy(rsa, mbedtls_pk_rsa(pk));
    if (ret != 0) {
        rsa_free(rsa);
        mbedtls_pk_free(&pk);
        return false;
    }
    mbedtls_pk_free(&pk);

    *rsa_context = rsa;
    return true;
}

/**
 * Retrieve the EC Private key from the password-protected PEM key data.
 *
 * @param[in]  pem_data      Pointer to the PEM-encoded key data to be retrieved.
 * @param[in]  pem_size      size of the PEM key data in bytes.
 * @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
 * @param[out] ec_context    Pointer to new-generated EC DSA context which contain the retrieved
 *                         EC private key component. Use ec_free() function to free the
 *                         resource.
 *
 * If pem_data is NULL, then return false.
 * If ec_context is NULL, then return false.
 *
 * @retval  true   EC Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 *
 **/
bool ec_get_private_key_from_pem(IN const uint8_t *pem_data, IN uintn pem_size,
                                 IN const char *password,
                                 OUT void **ec_context)
{
    int32_t ret;
    mbedtls_pk_context pk;
    mbedtls_ecdh_context *ecdh;
    uint8_t *new_pem_data;
    uintn password_len;

    if (pem_data == NULL || ec_context == NULL || pem_size > INT_MAX) {
        return false;
    }

    new_pem_data = NULL;
    if (pem_data[pem_size - 1] != 0) {
        new_pem_data = allocate_pool(pem_size + 1);
        if (new_pem_data == NULL) {
            return false;
        }
        copy_mem_s(new_pem_data, pem_size + 1, pem_data, pem_size);
        new_pem_data[pem_size] = 0;
        pem_data = new_pem_data;
        pem_size += 1;
    }

    mbedtls_pk_init(&pk);

    if (password != NULL) {
        password_len = ascii_str_len(password);
    } else {
        password_len = 0;
    }

    ret = mbedtls_pk_parse_key(&pk, pem_data, pem_size,
                               (const uint8_t *)password, password_len);

    if (new_pem_data != NULL) {
        free_pool(new_pem_data);
        new_pem_data = NULL;
    }

    if (ret != 0) {
        mbedtls_pk_free(&pk);
        return false;
    }

    if (mbedtls_pk_get_type(&pk) != MBEDTLS_PK_ECKEY) {
        mbedtls_pk_free(&pk);
        return false;
    }

    ecdh = allocate_zero_pool(sizeof(mbedtls_ecdh_context));
    if (ecdh == NULL) {
        mbedtls_pk_free(&pk);
        return false;
    }
    mbedtls_ecdh_init(ecdh);

    ret = mbedtls_ecdh_get_params(ecdh, mbedtls_pk_ec(pk),
                                  MBEDTLS_ECDH_OURS);
    if (ret != 0) {
        mbedtls_ecdh_free(ecdh);
        free_pool(ecdh);
        mbedtls_pk_free(&pk);
        return false;
    }
    mbedtls_pk_free(&pk);

    *ec_context = ecdh;
    return true;
}

/**
 * Retrieve the Ed Private key from the password-protected PEM key data.
 *
 * @param[in]  pem_data      Pointer to the PEM-encoded key data to be retrieved.
 * @param[in]  pem_size      size of the PEM key data in bytes.
 * @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
 * @param[out] ecd_context    Pointer to new-generated Ed DSA context which contain the retrieved
 *                         Ed private key component. Use ecd_free() function to free the
 *                         resource.
 *
 * If pem_data is NULL, then return false.
 * If ecd_context is NULL, then return false.
 *
 * @retval  true   Ed Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 *
 **/
bool ecd_get_private_key_from_pem(IN const uint8_t *pem_data,
                                  IN uintn pem_size,
                                  IN const char *password,
                                  OUT void **ecd_context)
{
    return false;
}

/**
 * Retrieve the sm2 Private key from the password-protected PEM key data.
 *
 * @param[in]  pem_data      Pointer to the PEM-encoded key data to be retrieved.
 * @param[in]  pem_size      size of the PEM key data in bytes.
 * @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
 * @param[out] sm2_context   Pointer to new-generated sm2 context which contain the retrieved
 *                         sm2 private key component. Use sm2_free() function to free the
 *                         resource.
 *
 * If pem_data is NULL, then return false.
 * If sm2_context is NULL, then return false.
 *
 * @retval  true   sm2 Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 *
 **/
bool sm2_get_private_key_from_pem(IN const uint8_t *pem_data,
                                  IN uintn pem_size,
                                  IN const char *password,
                                  OUT void **sm2_context)
{
    return false;
}
