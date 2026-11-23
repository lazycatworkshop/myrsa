#if defined(NDEBUG)
#define RESTORE_NDEBUG
#undef NDEBUG
#endif

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "oid.h"

int main(void)
{
	assert(lookup_oid(NULL, 0) == OID_TYPES_UNKNOWN);

	const uint32_t oid_invalid[] = { 1, 2, 3 };
	assert(lookup_oid(oid_invalid, 3) == OID_TYPES_UNKNOWN);

	const uint32_t oid_first[] = { 1, 2 };
	assert(lookup_oid(oid_first, 2) == OID_TYPES_member_body);

	const uint32_t oid_middle[] = { 1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 1 };
	assert(lookup_oid(oid_middle, 11) ==
	       OID_TYPES_jurisdictionOfIncorporationLocalityName);

	const uint32_t oid_last[] = { 2, 23, 140, 1, 2, 1 };
	assert(lookup_oid(oid_last, 6) == OID_TYPES_domain_validated);

	/* Every enum name must have a row, and no two rows may share an OID. */
	for (int i = 0; i < OID_TYPES_COUNT; i++)
		assert(lookup_oid(oid_database[i].oid,
				  oid_database[i].oid_len) == i);

	return 0;
}

#if defined(RESTORE_NDEBUG)
#define NDEBUG
#undef RESTORE_NDEBUG
#endif
