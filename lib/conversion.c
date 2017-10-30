//**********************************************************************;
// Copyright (c) 2017, SUSE Linux GmbH
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// 3. Neither the name of Intel Corporation nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;

#include <string.h>
#include <errno.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#include "conversion.h"
#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_util.h"

static bool tpm2_convert_pubkey_ssl(TPMT_PUBLIC *public, pubkey_format format, const char *path);

pubkey_format tpm2_parse_pubkey_format(const char *label) {
    if (strcasecmp(label, "der") == 0) {
        return pubkey_format_der;
    }
    else if (strcasecmp(label, "pem") == 0) {
        return pubkey_format_pem;
    }
    else if (strcasecmp(label, "tss") == 0) {
        return pubkey_format_tss;
    }

    LOG_ERR("Invalid public key output format '%s' specified", label);

    return pubkey_format_err;
}

signature_format tpm2_parse_signature_format(const char *label) {
    if (strcasecmp(label, "tss") == 0) {
        return signature_format_tss;
    }
    else if (strcasecmp(label, "plain") == 0) {
        return signature_format_plain;
    }

    LOG_ERR("Invalid signature output format '%s' specified", label);

    return signature_format_err;
}

static void print_ssl_error(const char *failed_action) {
    char errstr[256] = {0};
    unsigned long errnum = ERR_get_error();

    ERR_error_string_n(errnum, errstr, sizeof(errstr));
    LOG_ERR("%s: %s", failed_action, errstr);
}

bool tpm2_convert_pubkey(TPM2B_PUBLIC *public, pubkey_format format, const char *path) {

    if (format == pubkey_format_der || format == pubkey_format_pem) {
        return tpm2_convert_pubkey_ssl(&public->t.publicArea, format, path);
    }
    else if (format == pubkey_format_tss) {
        // save raw as is
        return files_save_bytes_to_file(path, (UINT8 *)public, sizeof(*public));
    }

    LOG_ERR("Unsupported public key output format.");
    return false;
}

static bool tpm2_convert_pubkey_ssl(TPMT_PUBLIC *public, pubkey_format format, const char *path) {
    bool ret = false;
    FILE *fp = NULL;
    RSA *ssl_rsa_key = NULL;

    // need this before the first SSL call for getting human readable error
    // strings in print_ssl_error()
    ERR_load_crypto_strings();

    if (public->type != TPM_ALG_RSA) {
        LOG_ERR("Unsupported key type for requested output format. Only RSA is supported.");
        goto error;
    }

    UINT32 exponent = (public->parameters).rsaDetail.exponent;
    if (exponent == 0) {
        exponent = RSA_DEFAULT_PUBLIC_EXPONENT;
    }

    // OpenSSL expects this in network byte order
    exponent = tpm2_util_hton_32(exponent);
    ssl_rsa_key = RSA_new();
    if (!ssl_rsa_key) {
        print_ssl_error("Failed to allocate OpenSSL RSA structure");
        goto error;
    }

    ssl_rsa_key->e = BN_bin2bn((void*)&exponent, sizeof(exponent), NULL);
    ssl_rsa_key->n = BN_bin2bn(
            (public->unique).rsa.t.buffer,
            (public->unique).rsa.t.size,
            NULL);

    if (!ssl_rsa_key->n || !ssl_rsa_key->e) {
        print_ssl_error("Failed to convert data to SSL internal format");
        goto error;
    }

    fp = fopen(path, "wb");
    if (!fp) {
        LOG_ERR("Failed to open public key output file '%s': %s",
            path, strerror(errno));
        goto error;
    }

    int ssl_res = 0;

    switch(format) {
    case pubkey_format_pem:
        ssl_res = PEM_write_RSA_PUBKEY(fp, ssl_rsa_key);
        break;
    case pubkey_format_der:
        ssl_res = i2d_RSA_PUBKEY_fp(fp, ssl_rsa_key);
        break;
    default:
        LOG_ERR("Invalid OpenSSL target format %d encountered", format);
        goto error;
    }

    if (ssl_res <= 0) {
        print_ssl_error("OpenSSL public key conversion failed");
        goto error;
    }

    ret = true;

error:
    if (fp) {
        fclose(fp);
    }
    if (ssl_rsa_key) {
        RSA_free(ssl_rsa_key);
    }
    ERR_free_strings();

    return ret;
}

bool tpm2_convert_signature(TPMT_SIGNATURE *signature, signature_format format, const char *path) {

    switch(format) {
    case signature_format_tss:
        /* TODO fix serialization */
        return files_save_bytes_to_file(path, (UINT8 *)signature,
            sizeof(*signature));
    case signature_format_plain: {
        UINT8 *buffer;
        UINT16 size;

        buffer = tpm2_extract_plain_signature(&size, signature);
        if (buffer == NULL) {
            return false;
        }

        bool ret = files_save_bytes_to_file(path, buffer, size);
        free(buffer);
        return ret;
    }
    default:
        LOG_ERR("Unsupported signature output format.");
        return false;
    }
}
