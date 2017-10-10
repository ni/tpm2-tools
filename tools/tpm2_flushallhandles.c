/*
 * Based on tpm2-tss commit e196c7e1007dcb1
 */

#include <sapi/tpm20.h>

#include "tpm2_util.h"
#include "tpm2_options.h"
#include "log.h"

TSS2_RC FlushAllLoadedHandles(TSS2_SYS_CONTEXT *sapi_context) {
    TPMS_CAPABILITY_DATA capabilityData;
    TSS2_RC rval = TSS2_RC_SUCCESS;
    TPMI_YES_NO moreData;
    UINT32 i;

    rval = Tss2_Sys_GetCapability(sapi_context, 0,
            TPM_CAP_HANDLES, TRANSIENT_FIRST,
            20, &moreData, &capabilityData, 0);

    if (rval != TSS2_RC_SUCCESS)
        return rval;

    if (capabilityData.data.handles.count != 0) {
        LOG_INFO( "Flushing loaded transient object handles: \n" );

        for (i = 0; i < capabilityData.data.handles.count; i++) {
            LOG_INFO("0x%8x, ", capabilityData.data.handles.handle[i]);

            rval = Tss2_Sys_FlushContext(sapi_context, capabilityData.data.handles.handle[i]);
            if(rval != TSS2_RC_SUCCESS) {
                LOG_ERR("Failed on object handle 0x%8x, ", capabilityData.data.handles.handle[i]);
                return rval;
            }
        }
        LOG_INFO( "\n" );
    }

    rval = Tss2_Sys_GetCapability(sapi_context, 0,
            TPM_CAP_HANDLES, LOADED_SESSION_FIRST,
            20, &moreData, &capabilityData, 0);

    if (rval != TSS2_RC_SUCCESS)
        return rval;

    if( capabilityData.data.handles.count != 0 ) {
        LOG_INFO( "Flushing loaded session handles: \n" );

        for( i = 0; i < capabilityData.data.handles.count; i++ ) {
            LOG_INFO("0x%8x, ", capabilityData.data.handles.handle[i] );

            rval = Tss2_Sys_FlushContext( sapi_context, capabilityData.data.handles.handle[i] );
            if( rval != TSS2_RC_SUCCESS ) {
                LOG_ERR("Failed on session handle 0x%8x, ", capabilityData.data.handles.handle[i]);
                return rval;
            }
        }
        LOG_INFO( "\n" );
    }

    return rval;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {
    UNUSED(flags);

    TSS2_RC rval = FlushAllLoadedHandles(sapi_context);
    if (rval != TSS2_RC_SUCCESS) {
        printf("ERROR: Failed to flush handles: 0x%x\n", rval);
        return 1;
    }

    return 0;
}
