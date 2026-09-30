.PHONY: all modules modules_install

all: modules

modules:
	$(MAKE) -C $(KERNEL_SRC) M=$(M) O=$(O) modules

modules_install:
	$(MAKE) -C $(KERNEL_SRC) M=$(M) O=$(O) \
		INSTALL_MOD_PATH=$(INSTALL_MOD_PATH) \
		INSTALL_MOD_DIR=$(INSTALL_MOD_DIR) modules_install
