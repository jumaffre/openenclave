// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "qeidentity.h"
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

oe_result_t oe_enforce_qe_identity(void)
{
    oe_result_t result = OE_FAILURE;
    oe_get_qe_identity_info_args_t qe_id_args = {0};
    const uint8_t* pem_pck_certificate = NULL;
    size_t pem_pck_certificate_size = 0;
    oe_cert_chain_t pck_cert_chain = {0};
    oe_parsed_qe_identity_info_t parsed_info = {0};

    OE_TRACE_INFO("Calling %s\n", __PRETTY_FUNCTION__);

    // fetch qe identity information
    OE_CHECK(oe_get_qe_identity_info(&qe_id_args));

    // TODO:
    // need to print out the identity information for callers 
    // from both enclave and host

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
                &pck_cert_chain));

    // parse identity info json blob
    printf("qe_identity.qe_id_info:[%s]\n", qe_id_args.qe_id_info);
    OE_CHECK(oe_parse_qe_identity_info_json(
                                    qe_id_args.qe_id_info,
                                    qe_id_args.qe_id_info_size,
                                    &parsed_info));

    // check identity
    oe_cleanup_qe_identity_info_args(&qe_id_args);
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
