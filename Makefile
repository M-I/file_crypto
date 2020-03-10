PROJECT = file_crypto
PROJECT_VERSION = 1.0.1

LOCAL_DEPS = crypto

include erlang.mk

EDOC_OPTS = {dir, "docs"}
docs:: edoc
