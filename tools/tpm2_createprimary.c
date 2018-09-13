//**********************************************************************;
// Copyright (c) 2015, Intel Corporation
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

#include <stdarg.h>
#include <stdbool.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>

#include <sapi/tpm20.h>
#include <tcti/tcti_socket.h>

#include "tpm2_options.h"
#include "tpm2_password_util.h"
#include "log.h"
#include "tpm2_util.h"
#include "files.h"
#include "tpm2_alg_util.h"
#include "tpm2_tool.h"

TPM_HANDLE handle2048rsa;

typedef struct tpm_createprimary_ctx tpm_createprimary_ctx;
struct tpm_createprimary_ctx {
    TPMS_AUTH_COMMAND session_data;
    TPM2B_SENSITIVE_CREATE inSensitive;
    TPM2B_PUBLIC in_public;
    TPMI_ALG_PUBLIC type;
    uint16_t aes_keysize;
    TPMI_ALG_HASH nameAlg;
    TPMI_RH_HIERARCHY hierarchy;
    bool is_policy_enforced;
    char *context_file;
    struct {
        UINT8 A : 1;
        UINT8 g : 1;
        UINT8 G : 1;
        UINT8 C : 1;
    } flags;
};

static tpm_createprimary_ctx ctx = {
    .session_data = {
        .sessionHandle = TPM_RS_PW,
        .nonce = TPM2B_EMPTY_INIT,
        .hmac = TPM2B_EMPTY_INIT,
        .sessionAttributes = SESSION_ATTRIBUTES_INIT(0),
    },
    .inSensitive = TPM2B_SENSITIVE_CREATE_EMPTY_INIT,
    .in_public = TPM2B_EMPTY_INIT,
    .type = TPM_ALG_RSA,
    .aes_keysize = 128,
    .nameAlg = TPM_ALG_SHA1,
    .hierarchy = TPM_RH_NULL,
    .is_policy_enforced = false
};

int setup_alg(void) {

    switch(ctx.nameAlg) {
    case TPM_ALG_SHA1:
    case TPM_ALG_SHA256:
    case TPM_ALG_SHA384:
    case TPM_ALG_SHA512:
    case TPM_ALG_SM3_256:
    case TPM_ALG_NULL:
        ctx.in_public.t.publicArea.nameAlg = ctx.nameAlg;
        break;
    default:
        LOG_ERR("nameAlg algrithm: 0x%0x not support !", ctx.nameAlg);
        return -1;
    }

    // First clear attributes bit field.
    *(UINT32 *)&(ctx.in_public.t.publicArea.objectAttributes) = 0;
    ctx.in_public.t.publicArea.objectAttributes.restricted = 1;
    //check if auth policy needs to be enforced
    ctx.in_public.t.publicArea.objectAttributes.userWithAuth = !ctx.is_policy_enforced;
    ctx.in_public.t.publicArea.objectAttributes.decrypt = 1;
    ctx.in_public.t.publicArea.objectAttributes.fixedTPM = 1;
    ctx.in_public.t.publicArea.objectAttributes.fixedParent = 1;
    ctx.in_public.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;
    ctx.in_public.t.publicArea.type = ctx.type;

    switch(ctx.type) {
    case TPM_ALG_RSA:
        ctx.in_public.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
        ctx.in_public.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = ctx.aes_keysize;
        ctx.in_public.t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
        ctx.in_public.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
        ctx.in_public.t.publicArea.parameters.rsaDetail.keyBits = 2048;
        ctx.in_public.t.publicArea.parameters.rsaDetail.exponent = 0;
        ctx.in_public.t.publicArea.unique.rsa.t.size = 0;
        break;

    case TPM_ALG_KEYEDHASH:
        ctx.in_public.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_XOR;
        ctx.in_public.t.publicArea.parameters.keyedHashDetail.scheme.details.exclusiveOr.hashAlg = TPM_ALG_SHA256;
        ctx.in_public.t.publicArea.parameters.keyedHashDetail.scheme.details.exclusiveOr.kdf = TPM_ALG_KDF1_SP800_108;
        ctx.in_public.t.publicArea.unique.keyedHash.t.size = 0;
        break;

    case TPM_ALG_ECC:
        ctx.in_public.t.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
        ctx.in_public.t.publicArea.parameters.eccDetail.symmetric.keyBits.aes = ctx.aes_keysize;
        ctx.in_public.t.publicArea.parameters.eccDetail.symmetric.mode.sym = TPM_ALG_CFB;
        ctx.in_public.t.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
        ctx.in_public.t.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
        ctx.in_public.t.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
        ctx.in_public.t.publicArea.unique.ecc.x.t.size = 0;
        ctx.in_public.t.publicArea.unique.ecc.y.t.size = 0;
        break;

    case TPM_ALG_SYMCIPHER:
        ctx.in_public.t.publicArea.parameters.symDetail.sym.algorithm = TPM_ALG_AES;
        ctx.in_public.t.publicArea.parameters.symDetail.sym.keyBits.sym = ctx.aes_keysize;
        ctx.in_public.t.publicArea.parameters.symDetail.sym.mode.sym = TPM_ALG_CFB;
        ctx.in_public.t.publicArea.unique.sym.t.size = 0;
        break;

    default:
        LOG_ERR("type algrithm: 0x%0x not support !", ctx.type);
        return -2;
    }
    return 0;
}

int create_primary(TSS2_SYS_CONTEXT *sapi_context) {
    UINT32 rval;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    TPM2B_DATA              outsideInfo = TPM2B_EMPTY_INIT;
    TPML_PCR_SELECTION      creationPCR;
    TPM2B_NAME              name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TPM2B_PUBLIC            outPublic = TPM2B_EMPTY_INIT;
    TPM2B_CREATION_DATA     creationData = TPM2B_EMPTY_INIT;
    TPM2B_DIGEST            creationHash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    TPMT_TK_CREATION        creationTicket = TPMT_TK_CREATION_EMPTY_INIT;

    sessionDataArray[0] = &ctx.session_data;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsData.cmdAuthsCount = 1;
    sessionsDataOut.rspAuthsCount = 1;

    ctx.inSensitive.t.size = ctx.inSensitive.t.sensitive.userAuth.b.size + 
        sizeof(ctx.inSensitive.t.size);

    if(setup_alg())
        return -1;

    creationPCR.count = 0;

    rval = Tss2_Sys_CreatePrimary(sapi_context, ctx.hierarchy, &sessionsData,
                                  &ctx.inSensitive, &ctx.in_public, &outsideInfo, &creationPCR,
                                  &handle2048rsa, &outPublic, &creationData, &creationHash,
                                  &creationTicket, &name, &sessionsDataOut);
    if(rval != TPM_RC_SUCCESS) {
        LOG_ERR("\nCreatePrimary Failed ! ErrorCode: 0x%0x\n", rval);
        return -2;
    }

    tpm2_tool_output("\nCreatePrimary Succeed ! Handle: 0x%8.8x\n\n", handle2048rsa);

    return 0;
}

static bool on_option(char key, char *value) {

    bool res;

    switch(key) {
    case 'A':
        if(strcmp(value, "o") == 0 || strcmp(value, "O") == 0)
            ctx.hierarchy = TPM_RH_OWNER;
        else if(strcmp(value, "p") == 0 || strcmp(value, "P") == 0)
            ctx.hierarchy = TPM_RH_PLATFORM;
        else if(strcmp(value, "e") == 0 || strcmp(value, "E") == 0)
            ctx.hierarchy = TPM_RH_ENDORSEMENT;
        else if(strcmp(value, "n") == 0 || strcmp(value, "N") == 0)
            ctx.hierarchy = TPM_RH_NULL;
        else {
            LOG_ERR("Invalid hierarchy, got\"%s\"", value);
            return false;
        }
        ctx.flags.A = 1;
        break;
    case 'P':
        res = tpm2_password_util_from_optarg(value, &ctx.session_data.hmac);
        if (!res) {
            LOG_ERR("Invalid parent key password, got\"%s\"", value);
            return false;
        }
        break;
    case 'K':
        res = tpm2_password_util_from_optarg(value, &ctx.inSensitive.t.sensitive.userAuth);
        if (!res) {
            LOG_ERR("Invalid new key password, got\"%s\"", value);
            return false;
        }
        break;
    case 'g':
        ctx.nameAlg = tpm2_alg_util_from_optarg(value);
        if(ctx.nameAlg == TPM_ALG_ERROR) {
            LOG_ERR("Invalid hash algorithm, got\"%s\"", value);
            return false;
        }
        ctx.flags.g = 1;
        break;
    case 'G':
        ctx.type = tpm2_alg_util_from_optarg(value);
        if(ctx.type == TPM_ALG_ERROR) {
            LOG_ERR("Invalid key algorithm, got\"%s\"", value);
            return false;
        }
        ctx.flags.G = 1;
        break;
    case 'B':
        if (!tpm2_util_string_to_uint16(value, &ctx.aes_keysize)) {
            LOG_ERR("Could not convert AES key size parameter to number, got: \"%s\"", value);
            return false;
        } else if (ctx.aes_keysize != 128 && ctx.aes_keysize != 192 && ctx.aes_keysize != 256) {
            LOG_ERR("AES key size must be 128, 192 or 256");
            return false;
        }
        break;
    case 'C':
        ctx.context_file = value;
        if(ctx.context_file == NULL || ctx.context_file[0] == '\0') {
            return false;
        }
        ctx.flags.C = 1;
        break;
    case 'L':
        ctx.in_public.t.publicArea.authPolicy.t.size = BUFFER_SIZE(TPM2B_DIGEST, buffer);
        if(!files_load_bytes_from_path(value, ctx.in_public.t.publicArea.authPolicy.t.buffer,
                                       &ctx.in_public.t.publicArea.authPolicy.t.size)) {
            return false;
        }
        break;
    case 'E':
        ctx.is_policy_enforced = true;
        break;
    case 'S':
        if (!tpm2_util_string_to_uint32(value, &ctx.session_data.sessionHandle)) {
            LOG_ERR("Could not convert session handle to number, got: \"%s\"",
                    value);
            return false;
        }
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      {"auth",1,NULL,'A'},
      {"pwdp",1,NULL,'P'},
      {"pwdk",1,NULL,'K'},
      {"halg",1,NULL,'g'},
      {"kalg",1,NULL,'G'},
      {"aes-key-size",1,NULL,'B'},
      {"context",1,NULL,'C'},
      {"policy-file",1,NULL,'L'},
      {"enforce-policy",1,NULL,'E'},
      {"input-session-handle",1,NULL,'S'},
      {0,0,0,0}
    };

    setbuf(stdout, NULL);
    setvbuf (stdout, NULL, _IONBF, BUFSIZ);

    *opts = tpm2_options_new("A:P:K:g:G:B:C:L:S:E", ARRAY_LEN(topts), topts, on_option, NULL);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);
    int returnVal = 0;

    if(ctx.flags.A == 1 && ctx.flags.g == 1 && ctx.flags.G == 1) {
        returnVal = create_primary(sapi_context);

        if (returnVal == 0 && ctx.flags.C) {
            returnVal = files_save_tpm_context_to_file(sapi_context, handle2048rsa,
                                                       ctx.context_file) != true;
        }

        if(returnVal) {
            return 1;
        }
    } else {
        return 1;
    }

    return 0;
}
