# At least for now, this is can't be built as a standalone project. Ie,
# it can only be built as a part of rpm build tree.
add_library(rpmpgp_legacy OBJECT)

option(WITH_LEGACY_OPENPGP "Use legacy OpenPGP parser (DEPRECATED)" OFF)

target_sources(rpmpgp_legacy PRIVATE
	rpmpgp_internal.h rpmpgp_internal.c rpmpgp_internal_armor.c
	rpmpgp_internal_dig.c rpmpgp_internal_lint.c
)
if (WITH_OPENSSL)
	find_package(OpenSSL 1.0.2 REQUIRED)
	target_sources(rpmpgp_legacy PRIVATE digest_openssl.c)
else()
	target_sources(rpmpgp_legacy PRIVATE digest_libgcrypt.c)
endif()
target_include_directories(rpmpgp_legacy PRIVATE ${CMAKE_SOURCE_DIR}/rpmio)
target_include_directories(rpmpgp_legacy PRIVATE ${Intl_INCLUDE_DIRS})

