OSS_HOME:=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# We'll set REGISTRY_ERR in builder.mk
docker.tag.dev = $(if $(DEV_REGISTRY),$(DEV_REGISTRY)/$*:$(patsubst sha256:%,%,$(shell cat $<)),$(REGISTRY_ERR))

images.docker-build = $(patsubst docker/%/Dockerfile,%,$(wildcard docker/*/Dockerfile)) test-auth-tls
images.cluster += $(images.docker-build)

include $(OSS_HOME)/build-aux/prelude.mk
include $(OSS_HOME)/build-aux/docker.mk
include $(OSS_HOME)/builder/builder.mk
include $(OSS_HOME)/build-aux-local/version.mk

$(call module,ambassador,$(OSS_HOME))

sync: python/ambassador/VERSION.py

test-%.docker.stamp: docker/test-%/Dockerfile FORCE
	docker build --quiet --iidfile=$@ $(<D)
test-auth-tls.docker.stamp: docker/test-auth/Dockerfile FORCE
	docker build --quiet --build-arg TLS=--tls --iidfile=$@ $(<D)

.SECONDARY:
