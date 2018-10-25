// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../common/qeidentity.h"
#include <openenclave/bits/safecrt.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/raise.h>

#include <stdio.h>
/**
 * Validate and copy buffer to enclave memory.
 */
static oe_result_t _copy_buffer_to_enclave(
    uint8_t** dst,
    size_t* dst_size,
    const uint8_t* src,
    size_t src_size)
{
    oe_result_t result = OE_FAILURE;
    if (!src || src_size == 0 || !oe_is_outside_enclave(src, src_size) ||
        dst == NULL || dst_size == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    *dst = oe_malloc(src_size);
    if (*dst == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    OE_CHECK(oe_memcpy_s(*dst, src_size, src, src_size));
    *dst_size = src_size;
    result = OE_OK;

done:
    return result;
}

/**
 * Call into host to fetch qe identity information.
 */
oe_result_t oe_get_qe_identity_info(oe_get_qe_identity_info_args_t* args)
{
    oe_result_t result = OE_FAILURE;
    size_t host_args_buffer_size = sizeof(*args);
    uint8_t* host_args_buffer = NULL;
    oe_get_qe_identity_info_args_t* host_args = NULL;
    oe_get_qe_identity_info_args_t tmp_args = {0};

    printf("Enclave: Calling %s\n", __PRETTY_FUNCTION__);

    if (args == NULL)
        OE_RAISE(OE_FAILURE);

    // allocate host memory to hold enclave arguments before calling into host 
    // for getting qe identity info
    host_args_buffer = oe_host_malloc(host_args_buffer_size);
    if (host_args_buffer == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    // Copy args struct.
    host_args = (oe_get_qe_identity_info_args_t*)host_args_buffer;
    *host_args = *args;


    printf("******************Soccerl 1 %s\n", __PRETTY_FUNCTION__);

    OE_CHECK(oe_ocall(OE_OCALL_GET_QE_ID_INFO, (uint64_t)host_args, NULL));

    printf("******************Soccerl 2 %s\n", __PRETTY_FUNCTION__);

    // Copy args to prevent TOCTOU issues.
    tmp_args = *host_args;

    printf("******************Soccerl 3 %s\n", __PRETTY_FUNCTION__);

    OE_CHECK(tmp_args.result);

    if (tmp_args.host_out_buffer == NULL ||
        !oe_is_outside_enclave(tmp_args.host_out_buffer, sizeof(uint8_t)))
        OE_RAISE(OE_UNEXPECTED);

    // Copy thr return data back into enclave address space
    // Ensure that all required outputs exist.
    OE_CHECK(
        _copy_buffer_to_enclave(
            &args->qe_id_info,
            &args->qe_id_info_size,
            tmp_args.qe_id_info,
            tmp_args.qe_id_info_size));
    OE_CHECK(
        _copy_buffer_to_enclave(
            &args->issuer_chain,
            &args->issuer_chain_size,
            tmp_args.issuer_chain,
            tmp_args.issuer_chain_size));

printf("******************Soccerl 4  %s args->qe_id_info = [%s]\n", __PRETTY_FUNCTION__, args->qe_id_info);
printf("******************Soccerl 5  %s args->issuer_chain = [%s]\n", __PRETTY_FUNCTION__, args->issuer_chain);

    // Check for null terminators.
    if (args->qe_id_info[args->qe_id_info_size - 1] != 0 ||
        args->issuer_chain[args->issuer_chain_size - 1] != 0)
        OE_RAISE(OE_INVALID_REVOCATION_INFO);

    result = OE_OK;
done:
    // Free args buffer and buffer allocated by host.
    if (host_args_buffer)
        oe_host_free(host_args_buffer);

    return result;
}

// Cleanup the args structure.
void oe_cleanup_qe_identity_info_args(oe_get_qe_identity_info_args_t* args)
{
    if (!args)
        return;

    // Free buffers on the enclave side.
    oe_free(args->issuer_chain);
    oe_free(args->qe_id_info);

    if (args->host_out_buffer)
        oe_host_free(args->host_out_buffer);
}