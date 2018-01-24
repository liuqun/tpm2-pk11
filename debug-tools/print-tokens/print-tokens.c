/* encoding:utf8 */

/* Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
 * All rights reserved.
 */

#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <dlfcn.h>

#include <p11-kit/pkcs11.h>
#include "pkcs11-probe.h"

void print_slot_info(CK_SLOT_INFO slot_info);
void print_token_info(CK_TOKEN_INFO token_info);

int main(int argc, char *argv[])
{
    CK_RV rc;
    CK_FUNCTION_LIST_PTR func_list = NULL;
    pkcs11_t pkcs11;
    int main_exit_code = 0;

    pkcs11 = new_pkcs11_instance();
    if (pkcs11_probe(pkcs11, "./libtpm2-pk11.so") != PROBE_SUCCESS) {
        fprintf(stderr, "Error: Failed to probe PKCS11 library\n");
        main_exit_code = 0x01;
        goto CLEANUP;
    }
    func_list = pkcs11_get_function_list(pkcs11);

    /* PKCS#11 library initialize */
    rc = func_list->C_Initialize(NULL);
    if (rc != CKR_OK) {
        fprintf(stderr, "Error initializing the PKCS#11 library: rc=%X\n", (int)rc);
        main_exit_code = 0x01;
        goto CLEANUP;
    }
    do {
        CK_ULONG slot_count = 0;

        /* Find out how many tokens are present in the slots */
        rc = func_list->C_GetSlotList(TRUE, NULL_PTR, &slot_count);
        if (rc != CKR_OK) {
            printf("Error getting number of slots: 0x%X\n", (int)rc);
            break;
        }
        if (slot_count > 0) {
            int i;
            CK_SLOT_ID_PTR slot_list = NULL;

            slot_list = (CK_SLOT_ID_PTR) malloc(slot_count * sizeof(CK_SLOT_ID));
            rc = func_list->C_GetSlotList(TRUE, slot_list, &slot_count);

            /* Display token info and slot info for each slot ID in "slot_list" */
            for (i = 0; i < slot_count; i++) {
                CK_RV token_info_err;
                CK_RV slot_info_err;
                CK_TOKEN_INFO token_info; ///< Structure to hold token information
                CK_SLOT_INFO slot_info; ///< Structure to hold slot information
                CK_SLOT_ID id;

                id = slot_list[i];
                token_info_err = func_list->C_GetTokenInfo(id, &token_info);
                slot_info_err = func_list->C_GetSlotInfo(id, &slot_info);
                if (token_info_err) {
                    printf("Error getting token info: 0x%X\n", (int)token_info_err);
                }
                if (slot_info_err) {
                    printf("Error getting the slot info: 0x%X\n", (int)slot_info_err);
                }
                if (token_info_err || slot_info_err) {
                    continue;
                }
                printf("Token 0x%x Info:\n", (int)id);
                print_token_info(token_info);
                printf("Slot 0x%x Info\n", (int)id);
                print_slot_info(slot_info);
            }

            free(slot_list);
            slot_list = NULL;
        }
    } while (0);

    /* PKCS#11 library finalize */
    rc = func_list->C_Finalize(NULL);
    if (rc != CKR_OK) {
        fprintf(stderr, "Error finalizing the PKCS#11 library: rc=%X\n", (int)rc);
        main_exit_code = 0x01;
        goto CLEANUP;
    }

    main_exit_code = 0;

CLEANUP:
    delete_pkcs11_instance(pkcs11);
    return main_exit_code;
}

void print_slot_info(CK_SLOT_INFO slot_info)
{
    /* Display the slot information */
    printf("\tDescription: %.64s\n", slot_info.slotDescription);
    printf("\tManufacturer: %.32s\n", slot_info.manufacturerID);
    printf("\tFlags: 0x%X\n", (int)slot_info.flags);
    printf("\tHardware Version: %d.%d\n", slot_info.hardwareVersion.major,
                                          slot_info.hardwareVersion.minor);
    printf("\tFirmware Version: %d.%d\n", slot_info.firmwareVersion.major,
                                          slot_info.firmwareVersion.minor);
}

void print_token_info(CK_TOKEN_INFO token_info)
{
    /* Display the token information */
    printf("\tLabel: %.32s\n", token_info.label);
    printf("\tManufacturer: %.32s\n", token_info.manufacturerID);
    printf("\tModel: %.16s\n", token_info.model);
    printf("\tSerial Number: %.16s\n", token_info.serialNumber);
    printf("\tFlags: 0x%X\n", (int)token_info.flags);
    printf("\tSessions: %d/%d\n", (int)token_info.ulSessionCount,
                                  (int)token_info.ulMaxSessionCount);
    printf("\tR/W Sessions: %d/%d\n", (int)token_info.ulRwSessionCount,
                                      (int)token_info.ulMaxRwSessionCount);
    printf("\tPIN Length: %d-%d\n", (int)token_info.ulMinPinLen,
                                    (int)token_info.ulMaxPinLen);
    printf("\tPublic Memory: 0x%X/0x%X\n", (int)token_info.ulFreePublicMemory,
                                           (int)token_info.ulTotalPublicMemory);
    printf("\tPrivate Memory: 0x%X/0x%X\n", (int)token_info.ulFreePrivateMemory,
                                           (int)token_info.ulTotalPrivateMemory);
    printf("\tHardware Version: %d.%d\n", (int)token_info.hardwareVersion.major,
                                          (int)token_info.hardwareVersion.minor);
    printf("\tFirmware Version: %d.%d\n", token_info.firmwareVersion.major,
                                          token_info.firmwareVersion.minor);
    printf("\tTime: %.16s\n", token_info.utcTime);
}
