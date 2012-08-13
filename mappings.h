typedef struct {
    uint32_t addr;
    uint32_t phyaddr;
    size_t   size;
    uint32_t saddr;
    uint32_t eaddr;
    int      in_use;
    int      regs;
} mapping_t;

#define NUM_MAPPINGS    200
#define INVALID_MAPPING 201
mapping_t **mappings;

void        mappings_trace_fd(int fd);
int         mappings_is_fd_traced(int fd);
void        mappings_trace_mmap(uint32_t address,uint32_t phyaddr,size_t length, int regs);
int         mappings_get_id(uint32_t address);
uint32_t    mappings_addr_to_base(uint32_t address);
uint32_t    mappings_addr_to_phys(uint32_t address);
uint32_t    mappings_is_addr_traced(uint32_t address);
int         mappings_is_regs(uint32_t address);
void        mappings_protect_all();
void        mappings_protect_mapping(uint32_t address);
void        mappings_unprotect_all();
void        mappings_unprotect_mapping(uint32_t address);
void        mappings_init();
void        hexdump(const void *data, int size);


/*
void add_file_descriptor(int fd);
int  trace_file_descriptor(int fd);
void add_mmap_region(void *addr,int phyaddr, size_t length, int regs);
void* mmap_addr_to_base(void* address);
int is_traced(void* address);
int is_regs(void* address);
void mmap_protect();
void mmap_unprotect();
void mappings_init();
void hexdump(const void *data, int size);
int get_mapping_id(void *address);
void* mapping_addr_to_base(void *address,int mapping);
uint32_t addr_to_phys(void* address);
void mmap_unprotect_region(void* address);
void mmap_protect_region(void* address);
*/
