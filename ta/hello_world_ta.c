/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <stdint.h>
#include <hello_world_ta.h>
#include <pta_attestation.h>
#include "utee_defines.h"

#define ATT_MAX_KEYSZ	4096

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("hello mister");
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;
	
	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("Hello World!\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	IMSG("BYE BYE!\n");
}

void GetFPs(int i, TEE_TASessionHandle sess, uint32_t param_types, TEE_Param params[4], uint32_t ret_orig){
	void** testBufToOverflow[5] = {0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff};
	if(i ==  0){
		while(true){
		
		}
		TEE_InvokeTACommand(sess,TEE_TIMEOUT_INFINITE, PTA_ATTESTATION_HASH_TA_MEMORY ,param_types, params, &ret_orig);
		return;
	}
	if(i == 5){
		for(int j = 0; j<8; j++){
			testBufToOverflow[j] = 0xbbbbbb;
		}
	}
	void* *fp;
	asm volatile ("mov %0, fp\n\t"
     : "=r" (fp)
    );

	IMSG("FP is now in base: %p", fp);
	
	void* *fp2 = *fp;
	IMSG("FP2 is now in base: %p", *(fp-1));
	GetFPs(i-1, sess, param_types, params, ret_orig);
}

//new: creates a new TA session, then new command
static TEE_Result ta_entry_attestation(uint32_t param_types, TEE_Param params[4])
{
	IMSG("Entered attestation");

	TEE_Time time;
	TEE_GetSystemTime(&time);
	IMSG("This is the cntpct: %u", time.seconds);


	uint8_t nonce[6] = { 0xa0, 0x98, 0x76, 0x54, 0x32, 0x10 }; // voor replay attacks?
	uint8_t measurement[TEE_SHA256_HASH_SIZE + ATT_MAX_KEYSZ / 8] = { };
	void* *testPointer = 0xFFFFFF;
	void* *testPointer2 = 0xFFFFFA;
	IMSG("Testpointer1 res: %p", testPointer);
	IMSG("Testpointer2 res: %p", testPointer2);
	TEE_Result res = TEE_ERROR_GENERIC;
	//TEE_Session session = { };
	uint32_t ret_orig = 0;
	
	param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					 TEE_PARAM_TYPE_MEMREF_OUTPUT,
					 TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
					 
	params[0].memref.buffer = nonce;
	params[0].memref.size = sizeof(nonce);
	params[1].memref.buffer = measurement;
	params[1].memref.size = sizeof(measurement);
	
	TEE_TASessionHandle sess = TEE_HANDLE_NULL;
	TEE_UUID att_uuid = PTA_ATTESTATION_UUID;
	//IMSG(myArray[2]);

	// TEEC niet bruikbaar vanaf TA? (ja)

	void** fp;
	asm volatile ("mov %0, fp\n\t"
     : "=r" (fp)
    );

	IMSG("FP is now before base: %p", fp);

	void* sp;
	asm volatile ("mov %0, sp\n\t"
     : "=r" (sp)
    );

	IMSG("SP is now before base: %p", sp);
	
	void* *fp2 = *fp;
	IMSG("FP2 is now before base: %p", *(fp-1));
	
	void* *fp3 = *fp2;
	IMSG("FP3 is now before base: %p", *(fp2-1));
	res = TEE_OpenTASession(&att_uuid, TEE_TIMEOUT_INFINITE, 0, NULL, &sess,
				&ret_orig);
	IMSG("Precheck res: %d", res);
	if (res) {
		IMSG("Going to out");
		//goto out;
	}

	GetFPs(10, sess, param_types, params, &ret_orig);

	res = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE, PTA_ATTESTATION_HASH_TA_MEMORY, param_types, params, &ret_orig);
				  

	IMSG("FP is now after: %p", fp);

	IMSG("Attestation complete");
	IMSG("Param types: %d", param_types);

	TEE_CloseTASession(sess);

	IMSG("Res: %d", res);

	return res;
}
//stop

static TEE_Result inc_value(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("Got value: %u from NW", params[0].value.a);
	params[0].value.a++;
	IMSG("Increase value to: %u", params[0].value.a);

	return TEE_SUCCESS;
}

static TEE_Result dec_value(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("Got value: %u from NW", params[0].value.a);
	params[0].value.a--;
	IMSG("Decrease value to: %u", params[0].value.a);

	return TEE_SUCCESS;
}
/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id) {
	case TA_HELLO_WORLD_CMD_INC_VALUE:
		return inc_value(param_types, params);
	case TA_HELLO_WORLD_CMD_DEC_VALUE:
		return dec_value(param_types, params);
	//new: invoking command from main.c, this will run the function in this file.
	case TA_HELLO_WORLD_HASH_TA_MEMORY:
		return ta_entry_attestation(param_types, params);
	//stop
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
