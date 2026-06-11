/*
 * Copyright(c) 2026 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * File: get_platform_info.c
 *
 * Description: Tool to retrieve platform information from SGX enclaves and output as JSON
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sgx_urts.h"
#include "sgx_report.h"
#include "sgx_pce.h"

// Forward declaration for sgx_ecall (internal SGX function)
extern sgx_status_t sgx_ecall(const sgx_enclave_id_t eid,
                              const int index,
                              const void* ocall_table,
                              void* ms);

#ifndef ID_ENCLAVE_PATH
#define ID_ENCLAVE_PATH "/usr/lib/x86_64-linux-gnu/libsgx_id_enclave.signed.so.1"
#endif
#ifndef PCE_ENCLAVE_PATH
#define PCE_ENCLAVE_PATH "/usr/lib/x86_64-linux-gnu/libsgx_pce.signed.so.1"
#endif

#define CPU_SVN_LENGTH                    16
#define ISV_SVN_LENGTH                    2
#define PCE_ID_LENGTH                     2

#define PPID_RSA3072_ENCRYPTED  3
#define REF_RSA_OAEP_3072_MOD_SIZE   384
#define REF_RSA_OAEP_3072_EXP_SIZE     4

// ECall indices for ID enclave functions
#define ECALL_IDE_GET_ID 0
#define ECALL_IDE_GET_PCE_ENCRYPT_KEY 1

// ECall index for PCE enclave function
#define ECALL_GET_PC_INFO 0

// Structure matching ide_get_id parameters
typedef struct {
    sgx_status_t retval;
    sgx_key_128bit_t* p_id;
} ms_ide_get_id_t;

// Structure matching ide_get_pce_encrypt_key parameters
typedef struct {
    sgx_status_t retval;
    sgx_target_info_t* p_pce_target;
    sgx_report_t* p_report;
    uint8_t crypto_suite;
    uint16_t cert_key_type;
    uint32_t key_size;
    uint8_t* p_pub_key;
} ms_ide_get_pce_encrypt_key_t;

// Structure matching get_pc_info parameters
typedef struct {
    sgx_status_t retval;
    sgx_report_t* p_report;
    uint8_t* p_public_key;
    uint32_t key_size;
    uint8_t crypto_suite;
    uint8_t* p_encrypted_ppid;
    uint32_t encrypted_ppid_buf_size;
    uint32_t* p_encrypted_ppid_out_size;
    sgx_pce_info_t* p_pce_info;
    uint8_t* p_signature_scheme;
} ms_get_pc_info_t;

static int load_enclave(const char* enclave_path, sgx_enclave_id_t* p_eid)
{
    sgx_launch_token_t launch_token = { 0 };
    int launch_token_updated = 0;

    sgx_status_t sgx_status = sgx_create_enclave(enclave_path,
        0,
        &launch_token,
        &launch_token_updated,
        p_eid,
        NULL);

    if (SGX_SUCCESS != sgx_status) {
        fprintf(stderr, "ERROR: Failed to load enclave: 0x%04x\n", sgx_status);
        fprintf(stderr, "Make sure %s exists and has correct permissions.\n", enclave_path);
        return -1;
    }

    return 0;
}

static void unload_enclave(sgx_enclave_id_t eid)
{
    if (eid == 0)
        return;

    sgx_destroy_enclave(eid);
}

static int call_ide_get_id(sgx_enclave_id_t eid, sgx_status_t* p_ecall_ret, sgx_key_128bit_t* p_platform_id)
{
    ms_ide_get_id_t ms;
    ms.p_id = p_platform_id;

    sgx_status_t status = sgx_ecall(eid, ECALL_IDE_GET_ID, NULL, &ms);
    if (status != SGX_SUCCESS) {
        fprintf(stderr, "ERROR: sgx_ecall failed: 0x%04x\n", status);
        return -1;
    }

    *p_ecall_ret = ms.retval;
    return 0;
}

static void print_json_output(const uint8_t* cpu_svn, const uint8_t* enc_ppid,
                              const uint8_t* pce_id, const uint8_t* pce_svn,
                              const uint8_t* qe_id)
{
    printf("{");

    // cpu_svn
    printf("\"cpu_svn\":\"");
    for (int i = 0; i < CPU_SVN_LENGTH; i++) {
        printf("%02x", cpu_svn[i]);
    }
    printf("\",");

    // enc_ppid
    printf("\"enc_ppid\":\"");
    for (int i = 0; i < REF_RSA_OAEP_3072_MOD_SIZE; i++) {
        printf("%02x", enc_ppid[i]);
    }
    printf("\",");

    // pce_id
    printf("\"pce_id\":\"");
    for (int i = 0; i < PCE_ID_LENGTH; i++) {
        printf("%02x", pce_id[i]);
    }
    printf("\",");

    // pce_svn
    printf("\"pce_svn\":\"");
    for (int i = 0; i < ISV_SVN_LENGTH; i++) {
        printf("%02x", pce_svn[i]);
    }
    printf("\",");

    // qe_id
    printf("\"qe_id\":\"");
    for (size_t i = 0; i < sizeof(sgx_key_128bit_t); i++) {
        printf("%02x", qe_id[i]);
    }
    printf("\"");

    printf("}\n");
}

static int call_ide_get_pce_encrypt_key(sgx_enclave_id_t eid,
                                         sgx_status_t* p_ecall_ret,
                                         sgx_target_info_t* p_pce_target,
                                         sgx_report_t* p_report,
                                         uint8_t* p_pub_key,
                                         uint32_t key_size)
{
    ms_ide_get_pce_encrypt_key_t ms;
    ms.p_pce_target = p_pce_target;
    ms.p_report = p_report;
    ms.crypto_suite = (uint8_t)PCE_ALG_RSA_OAEP_3072;
    ms.cert_key_type = (uint16_t)PPID_RSA3072_ENCRYPTED;
    ms.key_size = key_size;
    ms.p_pub_key = p_pub_key;

    sgx_status_t status = sgx_ecall(eid, ECALL_IDE_GET_PCE_ENCRYPT_KEY, NULL, &ms);
    if (status != SGX_SUCCESS) {
        fprintf(stderr, "ERROR: sgx_ecall (ide_get_pce_encrypt_key) failed: 0x%04x\n", status);
        return -1;
    }

    *p_ecall_ret = ms.retval;
    return 0;
}

static int call_get_pc_info(sgx_enclave_id_t eid,
                             sgx_status_t* p_ecall_ret,
                             sgx_report_t* p_report,
                             uint8_t* p_public_key,
                             uint32_t key_size,
                             uint8_t* p_encrypted_ppid,
                             uint32_t encrypted_ppid_buf_size,
                             sgx_pce_info_t* p_pce_info)
{
    uint32_t encrypted_ppid_out_size = 0;
    uint8_t signature_scheme = 0;

    ms_get_pc_info_t ms;
    ms.p_report = p_report;
    ms.p_public_key = p_public_key;
    ms.key_size = key_size;
    ms.crypto_suite = (uint8_t)PCE_ALG_RSA_OAEP_3072;
    ms.p_encrypted_ppid = p_encrypted_ppid;
    ms.encrypted_ppid_buf_size = encrypted_ppid_buf_size;
    ms.p_encrypted_ppid_out_size = &encrypted_ppid_out_size;
    ms.p_pce_info = p_pce_info;
    ms.p_signature_scheme = &signature_scheme;

    sgx_status_t status = sgx_ecall(eid, ECALL_GET_PC_INFO, NULL, &ms);
    if (status != SGX_SUCCESS) {
        fprintf(stderr, "ERROR: sgx_ecall (get_pc_info) failed: 0x%04x\n", status);
        return -1;
    }

    *p_ecall_ret = ms.retval;

    // Validate signature scheme
    if (signature_scheme != PCE_NIST_P256_ECDSA_SHA256) {
        fprintf(stderr, "ERROR: PCE returned incorrect signature scheme.\n");
        return -1;
    }

    // Validate encrypted PPID size
    if (encrypted_ppid_out_size != REF_RSA_OAEP_3072_MOD_SIZE) {
        fprintf(stderr, "ERROR: PCE returned incorrect encrypted PPID size.\n");
        return -1;
    }

    return 0;
}

static int get_platform_info(void)
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    sgx_enclave_id_t id_enclave_eid = 0;
    sgx_enclave_id_t pce_enclave_eid = 0;
    sgx_target_info_t pce_target_info = {0};
    sgx_report_t id_enclave_report = {0};
    uint8_t enc_public_key[REF_RSA_OAEP_3072_MOD_SIZE + REF_RSA_OAEP_3072_EXP_SIZE] = {0};
    uint8_t encrypted_ppid[REF_RSA_OAEP_3072_MOD_SIZE] = {0};
    sgx_pce_info_t pce_info = {0};
    sgx_key_128bit_t platform_id = {0};
    int ret = 0;

    // Load ID enclave
    if (load_enclave(ID_ENCLAVE_PATH, &id_enclave_eid) != 0) {
        ret = -1;
        goto cleanup;
    }

    // Load PCE enclave
    if (load_enclave(PCE_ENCLAVE_PATH, &pce_enclave_eid) != 0) {
        ret = -1;
        goto cleanup;
    }

    // Get PCE target info
    sgx_status = sgx_get_target_info(pce_enclave_eid, &pce_target_info);
    if (SGX_SUCCESS != sgx_status) {
        fprintf(stderr, "ERROR: Failed to get pce target info: 0x%04x\n", sgx_status);
        ret = -1;
        goto cleanup;
    }

    // Get PCE encryption key from ID enclave
    if (call_ide_get_pce_encrypt_key(id_enclave_eid, &sgx_status, &pce_target_info,
                                      &id_enclave_report, enc_public_key,
                                      sizeof(enc_public_key)) != 0) {
        ret = -1;
        goto cleanup;
    }

    if (SGX_SUCCESS != sgx_status) {
        fprintf(stderr, "ERROR: ide_get_pce_encrypt_key returned error: 0x%04x\n", sgx_status);
        ret = -1;
        goto cleanup;
    }

    // Call get_pc_info on PCE enclave
    if (call_get_pc_info(pce_enclave_eid, &sgx_status, &id_enclave_report,
                         enc_public_key, sizeof(enc_public_key),
                         encrypted_ppid, sizeof(encrypted_ppid),
                         &pce_info) != 0) {
        ret = -1;
        goto cleanup;
    }

    if (SGX_SUCCESS != sgx_status) {
        fprintf(stderr, "ERROR: get_pc_info returned error: 0x%04x\n", sgx_status);
        ret = -1;
        goto cleanup;
    }

    // Get platform ID (QE ID)
    if (call_ide_get_id(id_enclave_eid, &sgx_status, &platform_id) != 0) {
        ret = -1;
        goto cleanup;
    }

    if (SGX_SUCCESS != sgx_status) {
        fprintf(stderr, "ERROR: ide_get_id returned error: 0x%04x\n", sgx_status);
        ret = -1;
        goto cleanup;
    }

    // Print JSON output
    print_json_output(id_enclave_report.body.cpu_svn.svn, encrypted_ppid,
                      (uint8_t*)&pce_info.pce_id, (uint8_t*)&pce_info.pce_isv_svn,
                      (uint8_t*)&platform_id);

cleanup:
    unload_enclave(pce_enclave_eid);
    unload_enclave(id_enclave_eid);
    return ret;
}

int main(void)
{
    // Get all platform information and output as JSON
    return get_platform_info();
}
