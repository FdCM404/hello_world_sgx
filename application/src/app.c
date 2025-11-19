#include <stdio.h>

#include "app.h"

#include "sgx_urts.h"    // Necessário para as funções de runtime do SGX
#include "enclave_u.h"   // Ficheiro gerado automaticamente a partir do EDL

sgx_enclave_id_t global_eid = 0;

#define ENCLAVE_FILENAME "enclave.signed.so"

void ocall_print_string(const char* str)
{
    printf("%s", str);
}

int main(int argc, char const *argv[])
{
    (void)(argc);
    (void)(argv);

    sgx_status_t ret = SGX_SUCCESS;

    // Criar e init o enclave
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);

    if (ret != SGX_SUCCESS) 
    
    {
        printf("Erro: falha ao criar o enclave. Código: 0x%x\n", ret);
        return -1;
    }

    printf("Enclave criado com sucesso.\n");

    // Chamar o Enclave (ECALL)
    sgx_status_t ecall_status = SGX_SUCCESS;
    ret = ecall_hello_world(global_eid); // A chamada ECALL real


    if (ret != SGX_SUCCESS) {
        printf("Erro: falha ao executar a ECALL. Código: 0x%x", ret);
        sgx_destroy_enclave(global_eid); // Limpar em caso de erro
        return -1;
    }


    printf("ECALL executada com sucesso.\n");

    // 3. Destruir o Enclave
    sgx_destroy_enclave(global_eid);

    return 0;
}
