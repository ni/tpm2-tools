//**********************************************************************;
// Copyright (c) 2017, National Instruments
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

#include <stdio.h>
#include "log.h"
#include "tpm2_util.h"

static UINT8 fdread_uint8(FILE* fd, bool* read_error) {
    UINT8 x;
    if(fread(&x, sizeof(UINT8), 1, fd) != 1) {
        x = 0;
        *read_error = true;
    }
    return x;
}

static UINT16 fdread_uint16(FILE* fd, bool* read_error) {
    UINT16 x;
    if(fread(&x, sizeof(UINT16), 1, fd) != 1) {
        x = 0;
        *read_error = true;
    }
    x = tpm2_util_ntoh_16(x);
    return x;
}

static UINT32 fdread_uint32(FILE* fd, bool* read_error) {
    UINT32 x;
    if(fread(&x, sizeof(UINT32), 1, fd) != 1) {
        x = 0;
        *read_error = true;
    }
    x = tpm2_util_ntoh_32(x);
    return x;
}

static UINT64 fdread_uint64(FILE* fd, bool* read_error) {
    UINT64 x;
    if(fread(&x, sizeof(UINT64), 1, fd) != 1) {
        x = 0;
        *read_error = true;
    }
    x = tpm2_util_ntoh_64(x);
    return x;
}

static bool print_hex(FILE* fd, long unsigned int size, bool* read_error) {
    while(size-- > 0) {
        printf("%2.2x", (unsigned int)fdread_uint8(fd, read_error));
        if(*read_error) {
            printf("\n");
            return false;
        }
    }
    printf("\n");
    return true;
}

static bool print_tpm2b_hex(FILE* fd, bool* read_error) {
    const UINT16 size = fdread_uint16(fd, read_error);
    if(*read_error) {
        return false;
    }
    return print_hex(fd, size, read_error);
}

static bool print_quote(const char* const filename) {
    bool result = false;
    bool read_error = false;

    printf("filename=%s\n", filename);
    FILE* fd = fopen(filename, "rb");
    if(!fd) {
        LOG_ERR("%s: Could not open file", filename);
        return result;
    }

    // check magic
    if(fdread_uint32(fd, &read_error) != TPM_GENERATED_VALUE || read_error) {
        LOG_ERR("%s: Bad magic", filename);
        goto end;
    }

    // check type (must be a quote)
    if(fdread_uint16(fd, &read_error) != TPM_ST_ATTEST_QUOTE || read_error) {
        LOG_ERR("%s: Not a quote object", filename);
        goto end;
    }

    // print qualifiedSigner (TPM2B_*)
    printf("qualifiedSigner=");
    if(!print_tpm2b_hex(fd, &read_error)) {
        LOG_ERR("%s: Failed to print qualifiedSigner", filename);
        goto end;
    }

    // print extraData (TPM2B_*)
    printf("extraData=");
    if(!print_tpm2b_hex(fd, &read_error)) {
        LOG_ERR("%s: Failed to print extraData", filename);
        goto end;
    }

    // print clockInfo (TPMS_CLOCK_INFO)
    printf("clockInfo.clock=%llu\n", (long long unsigned int)fdread_uint64(fd, &read_error));
    printf("clockInfo.resetCount=%lu\n", (long unsigned int)fdread_uint32(fd, &read_error));
    printf("clockInfo.restartCount=%lu\n", (long unsigned int)fdread_uint32(fd, &read_error));
    printf("clockInfo.safe=%u\n", (unsigned int)fdread_uint8(fd, &read_error));
    if(read_error) {
        LOG_ERR("%s: Failed to read clockInfo", filename);
        goto end;
    }

    // skip over firmwareVersion (UINT64)
    printf("firmwareVersion=0x%llx\n", (long long unsigned int)fdread_uint64(fd, &read_error));
    if(read_error) {
        LOG_ERR("%s: Failed to read firmwareVersion", filename);
        goto end;
    }

    // read over TPML_PCR_SELECTION (UINT32 count followed by TPMS_PCR_SELECTION[])
    const UINT32 pcr_selection_count = fdread_uint32(fd, &read_error);
    printf("attested.quote.pcrSelect.count=%lu\n", (long unsigned int)pcr_selection_count);
    for(long unsigned int i = 0; i < pcr_selection_count; ++i) {
        // print hash type (TPMI_ALG_HASH)
        printf("attested.quote.pcrSelect[%lu].hash=%u\n", i, (unsigned int)fdread_uint16(fd, &read_error));
        if(read_error) {
            LOG_ERR("%s: Failed to read PCR hash type", filename);
            goto end;
        }

        // print size of PCR selection
        const UINT8 sizeofSelect = fdread_uint8(fd, &read_error);
        printf("attested.quote.pcrSelect[%lu].sizeofSelect=%u\n", i, (unsigned int)sizeofSelect);
        if(read_error) {
            LOG_ERR("%s: Failed to read sizeofSelect", filename);
            goto end;
        }

        // print PCR selection in hex
        printf("attested.quote.pcrSelect[%lu].pcrSelect=", i);
        if(!print_hex(fd, sizeofSelect, &read_error)) {
            LOG_ERR("%s: Failed to read PCR selection", filename);
            goto end;
        }
    }

    // print digest size
    const UINT16 digest_size = fdread_uint16(fd, &read_error);
    printf("attested.quote.pcrDigest.size=%lu\n", (long unsigned int)digest_size);
    if(digest_size < 1) {
        LOG_ERR("%s: Digest missing (zero size)", filename);
        goto end;
    }

    // print digest in hex
    printf("attested.quote.pcrDigest=");
    if(!print_hex(fd, digest_size, &read_error)) {
        goto end;
    }

    // success
    result = true;

    end:
    fclose(fd);
    if(read_error) {
        LOG_ERR("%s: File too short", filename);
        result = false;
    }
    return result;
}

int main(int argc, char *argv[]) {
    int result = 0;

    if(argc < 2) {
        LOG_ERR("Must specify at least one quote file");
        result = 1;
    }

    for(int i = 1; i < argc; ++i) {
        if(!print_quote(argv[i])) {
            result = 1;
        }
        if(i + 1 < argc) {
            printf("\n");
        }
    }

    return result;
}
