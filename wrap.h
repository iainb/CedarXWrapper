#ifdef DEBUG
# define DEBUGF(a...)							\
	do {								\
		fprintf(stderr, "%s[%d]", __FILE__, __LINE__);	\
		fprintf(stderr, ##a);				\
	} while(0)
#else
# define DEBUGF(a...)
#endif

#define special_offset 0xdc8d8000

// ioctl for cedar_dev

enum IOCTL_CMD {
	IOCTL_UNKOWN = 0x100,
	IOCTL_GET_ENV_INFO,
	IOCTL_WAIT_VE,
	IOCTL_RESET_VE,
	IOCTL_ENABLE_VE,
	IOCTL_DISABLE_VE,
	IOCTL_SET_VE_FREQ,

	IOCTL_CONFIG_AVS2 = 0x200,
	IOCTL_GETVALUE_AVS2 ,
	IOCTL_PAUSE_AVS2 ,
	IOCTL_START_AVS2 ,
	IOCTL_RESET_AVS2 ,
	IOCTL_ADJUST_AVS2,
	IOCTL_ENGINE_REQ,
	IOCTL_ENGINE_REL,
	IOCTL_ENGINE_CHECK_DELAY,
	IOCTL_GET_IC_VER,

	IOCTL_ADJUST_AVS2_ABS,
	IOCTL_FLUSH_CACHE,
};

void wrap_init(void);
