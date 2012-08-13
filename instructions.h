
typedef struct {
    uint64_t value;
    uint32_t address;
} instruction_data_t;

typedef struct {
    char                type[5];
    instruction_data_t  data[14];
    int                 count;
} instruction_info_t;

void handle_instruction(uint32_t instruction,uint32_t fault_addr,ucontext_t *uc,instruction_info_t *res);
