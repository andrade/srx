CC := gcc

PROJ_DIR = $(CURDIR)
$(info [PROJ_DIR] "$(PROJ_DIR)")

SRX_OPENSSL ?= /home/daniel/tmp/openssl/openssl111a

CPPFLAGS := -Iinclude -I$(SRX_OPENSSL)/include -DDEBUG
CFLAGS := -m64 -Og -g -Wall -Wextra -std=c11 -fPIC
LDFLAGS := -L$(SRX_OPENSSL)/lib \
		-Wl,-rpath,$(SRX_OPENSSL)/lib,--disable-new-dtags
LDLIBS := -lssl -lcrypto

all: static/libfoossl_common.a \
			static/libfoossl_client.a static/libfoossl_server.a \
			bin/test/client bin/test/server
	$(info [  MAKE  ] $(notdir $^))

obj/%.o: src/%.c
	@mkdir -p obj
	@$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

static/libfoossl_common.a: obj/foossl_common.o
	@mkdir -p static
	@ar rcs $@ $^

#ifeq ($(FLAG_SOFT_LINK),1)
#	mkdir -p $(MAIN_STATIC)
#	$(info $(MAIN_STATIC))
#	ln -s $@ $(MAIN_STATIC)/$(notdir $@)
#else
#	$(info MAINS NOT SET $(MAIN_STATIC))
#endif

static/libfoossl_client.a: obj/foossl_client.o
	@mkdir -p static
	@ar rcs $@ $^

static/libfoossl_server.a: obj/foossl_server.o
	@mkdir -p static
	@ar rcs $@ $^

tls/key.pem tls/cert.pem:
	@mkdir -p tls
	@openssl req -x509 -newkey rsa:4096 \
			-keyout tls/key.pem -out tls/cert.pem \
			-subj '/C=PT/ST=Lisboa/L=Lisboa/O=INESC-ID/OU=GSD/CN=domain.fake' \
			-days 365 -nodes

obj/test/%.o: test/%.c
	@mkdir -p obj/test
	@$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

bin/test/client: obj/test/client.o \
			static/libfoossl_common.a static/libfoossl_client.a \
			tls/key.pem tls/cert.pem
	@mkdir -p bin/test
	@$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(filter-out %.pem,$^) \
			-o $@ $(LDLIBS)

bin/test/server: obj/test/server.o \
			static/libfoossl_common.a static/libfoossl_server.a \
			tls/key.pem tls/cert.pem
	@mkdir -p bin/test
	@$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(filter-out %.pem,$^) \
			-o $@ $(LDLIBS)

#ifeq ($(FLAG_SOFT_LINK),1)
#$(info [MAIN_DIR] "$(MAIN_DIR)")
#else
#$(info not set)
#endif

# Create soft links for public interface and static archive

#link: include/*.h static/libfoossl_client.a static/libfoossl_common.a static/libfoossl_server.a
#	$(info processing soft links...)
#ifeq ($(FLAG_SOFT_LINK),1)
#	@mkdir -p $(MAIN_STATIC)
#	@$(foreach var,$(filter %.a,$^),ln -sf $(var) $(MAIN_STATIC)/$(notdir $(var));)
#	@mkdir -p $(MAIN_INCLUDE)
#	@$(foreach var,$(filter %.h,$^),ln -sf $(var) $(MAIN_INCLUDE)/$(notdir $(var));)
#endif

# Maintenance

TRASH := bin obj static tls
.PHONY: clean
clean:
	@rm -rf $(TRASH)
	$(info [   RM   ] $(TRASH))
