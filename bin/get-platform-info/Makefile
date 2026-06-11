#
# Copyright(c) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
#

######## App Settings ########
App_C_Files := get_platform_info.c
App_Include_Paths := -I/usr/include

ID_ENCLAVE_PATH  ?= /usr/lib/x86_64-linux-gnu/libsgx_id_enclave.signed.so.1
PCE_ENCLAVE_PATH ?= /usr/lib/x86_64-linux-gnu/libsgx_pce.signed.so.1

App_C_Flags := -fPIE -Wno-attributes \
               -O2 -D_FORTIFY_SOURCE=2 \
               -fstack-protector-strong \
               -fstack-clash-protection \
               $(App_Include_Paths) \
               -DID_ENCLAVE_PATH=\"$(ID_ENCLAVE_PATH)\" \
               -DPCE_ENCLAVE_PATH=\"$(PCE_ENCLAVE_PATH)\"

App_Link_Flags := -pie -lsgx_urts -lpthread \
                  -Wl,-z,relro,-z,now \
                  -Wl,-z,nodlopen \
                  -Wl,-z,noexecstack

App_C_Objects := $(App_C_Files:.c=.o)

App_Name := get_platform_info

######## Build Settings ########
.PHONY: all run clean

all: $(App_Name)

######## App Objects ########
get_platform_info.o: get_platform_info.c
	@echo "CC  <=  $<"
	@$(CC) $(App_C_Flags) -c $< -o $@

$(App_Name): $(App_C_Objects)
	@echo "LINK =>  $@"
	@$(CC) $^ -o $@ $(App_Link_Flags)
	@echo "Build complete."

run: $(App_Name)
	@echo "Running $(App_Name)..."
	@./$(App_Name)

clean:
	@rm -f $(App_Name) $(App_C_Objects)
	@echo "Clean complete."
