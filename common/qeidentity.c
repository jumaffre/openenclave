// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "revocation.h"
#include <openenclave/bits/safecrt.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/crl.h>
#include <openenclave/internal/datetime.h>
#include <openenclave/internal/ec.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgxcertextensions.h>
#include <openenclave/internal/sha.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include "common.h"
#include "tcbinfo.h"

#ifdef OE_USE_LIBSGX

// Defaults to Intel SGX 1.8 Release Date.
oe_datetime_t _sgx_minimim_crl_tcb_issue_date = {2017, 3, 17};

oe_result_t __oe_sgx_set_minimum_crl_tcb_issue_date(
    uint32_t year,
    uint32_t month,
    uint32_t day,
    uint32_t hours,
    uint32_t minutes,
    uint32_t seconds)
{
    oe_result_t result = OE_FAILURE;
    oe_datetime_t tmp = {year, month, day, hours, minutes, seconds};

    OE_CHECK(oe_datetime_is_valid(&tmp));
    _sgx_minimim_crl_tcb_issue_date = tmp;

    result = OE_OK;
done:
    return result;
}

/**
 * Parse sgx extensions from given cert.
 */
static oe_result_t _parse_sgx_extensions(
    oe_cert_t* leaf_cert,
    ParsedExtensionInfo* parsed_extension_info)
{
    oe_result_t result = OE_FAILURE;

    // The size of buffer required to parse extensions is not known beforehand.
    size_t buffer_size = 1024;
    uint8_t* buffer = NULL;

    buffer = (uint8_t*)malloc(buffer_size);
    if (buffer == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    // Try parsing the extensions.
    result = ParseSGXExtensions(
        leaf_cert, buffer, &buffer_size, parsed_extension_info);

    if (result == OE_BUFFER_TOO_SMALL)
    {
        // Allocate larger buffer. extensions_buffer_size contains required size
        // of buffer.
        free(buffer);
        buffer = (uint8_t*)malloc(buffer_size);

        result = ParseSGXExtensions(
            leaf_cert, buffer, &buffer_size, parsed_extension_info);
    }

done:
    free(buffer);
    return result;
}

typedef struct _url
{
    char str[256];
} url_t;



static void _trace_datetime(const char* msg, const oe_datetime_t* date)
{
#if (OE_TRACE_LEVEL == OE_TRACE_LEVEL_INFO)
    char str[21];
    size_t size = sizeof(str);
    oe_datetime_to_string(date, str, &size);
    OE_TRACE_INFO("%s%s\n", msg, str);
#endif
}


typedef struct _oe_parsed_qe_identity_info
{
    uint32_t version;
    oe_datetime_t issue_date;
    oe_datetime_t next_update;

    uint32_t miscselect;        // The MISCSELECT that must be set
    uint32_t miscselectMask;    // Mask of MISCSELECT to enforce

    // TODO: find out what attributes are!

    sgx_attributes_t attributes; // ATTRIBUTES Flags Field 
    uint32_t         attributesMask; // string

    uint8_t mrsigner[OE_SHA256_SIZE]; // MRSIGNER of the enclave

    uint16_t isvprodid; // ISV assigned Product ID
    uint16_t isvsvn; // ISV assigned SVN

    uint8_t signature[64];
} oe_parsed_qe_identity_info_t;


oe_result_t oe_parse_qe_identity_info_json(
    const uint8_t* info_json,
    size_t info_json_size,
    oe_parsed_qe_identity_info_t* parsed_info)
{
    oe_result_t result = OE_OK;
    return result;
}

oe_result_t oe_enforce_qe_identity()
{
    oe_result_t result = OE_FAILURE;
    oe_get_qe_identity_info_args_t qe_id_args = {0};

    OE_TRACE_INFO("Calling %s\n", __PRETTY_FUNCTION__);

    // fetch qe identity information
    OE_CHECK(oe_get_qe_identity_info(&qe_id_args));

    pem_pck_certificate = qe_id_args.issuer_chain;
    pem_pck_certificate_size = qe_id_args.issuer_chain_size;


    // validate the cert chain.
    OE_CHECK(
            oe_cert_chain_read_pem(
                &pck_cert_chain,
                pem_pck_certificate,
                pem_pck_certificate_size));

    // verify qe identity signature
    printf("qe_identity.issuer_chain:[%s]\n", qe_id_args.issuer_chain);
    OE_CHECK(oe_verify_tcb_signature(
                qe_id_args.qe_id_info,
                qe_id_args.qe_id_info_size,
                (sgx_ecdsa256_signature_t*)qe_id_args.signature,
                &qe_id_args.issuer_chain));

    // parse identity info json blob
    printf("qe_identity.qe_id_info:[%s]\n", test->qe_id_info);
    OE_CHECK(oe_parse_qe_identity_info_json(
                                    qe_id_args.qe_id_info,
                                    qe_id_args.qe_id_info_size,
                                    &parsed_info));    

    // check identity
    OE_CHECK(oe_cleanup_qe_identity_info_args(&args));
    result = OE_OK;

done:
    return result;
}

/*
{

    oe_result_t result = OE_FAILURE;
    sgx_qe_identity_info_t *identity = NULL;
    oe_parsed_qe_identity_info_t parsed_info = {0};
    oe_cert_chain_t pck_cert_chain = {0};
    const uint8_t* pem_pck_certificate = NULL;
    size_t pem_pck_certificate_size = 0;

    printf("===========qe_identity ========\n");
    OE_TRACE_INFO("Calling %s\n", __PRETTY_FUNCTION__);

    // fetch qe identity information
    _get_qe_identity_info(&identity);

    pem_pck_certificate = identity.issuer_chain;
    pem_pck_certificate_size = identity.issuer_chain_size;


    // validate the cert chain.
    OE_CHECK(
            oe_cert_chain_read_pem(
                &pck_cert_chain,
                pem_pck_certificate,
                pem_pck_certificate_size));

    // verify qe identity signature
    printf("qe_identity.issuer_chain:[%s]\n", test->issuer_chain);
    OE_CHECK(oe_verify_tcb_signature(
                identity.qe_id_info,
                identity.qe_id_info_size,
                (sgx_ecdsa256_signature_t*)identity.signature,
                &tcb_issuer_chain));

    // parse identity info json blob
    printf("qe_identity.qe_id_info:[%s]\n", test->qe_id_info);
    OE_CHECK(oe_parse_qe_identity_info_json(
                                    identity->qe_id_info,
                                    identity->qe_id_info_size,
                                    &parsed_info));    

    // check identity

    _free_qe_identity_info(identity);
    printf("===========qe_identity ========\n");

    result = OE_OK;
    return result;

}
*/
#endif
