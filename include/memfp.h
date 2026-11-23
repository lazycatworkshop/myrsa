/* memfp.h - Memory file pointer abstraction */

#ifndef MEMFP_H
#define MEMFP_H
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

struct memfp {
	const uint8_t *buf;
	const uint8_t *pos;
	const uint8_t *end;
};

static inline void memfp_open(struct memfp *mp, const uint8_t *buf, size_t len)
{
	mp->buf = buf;
	mp->pos = buf;
	mp->end = buf + len;
}

static inline int mgetc(struct memfp *mp)
{
	if (mp->pos >= mp->end) {
		return EOF;
	}
	int c = *mp->pos;
	(mp->pos)++;
	return c;
}

static inline void mungetc(struct memfp *mp)
{
	(mp->pos)--;
}

static inline int mpeekc(struct memfp *mp)
{
	if (mp->pos >= mp->end) {
		return EOF;
	}
	return *mp->pos;
}

static inline long mtell(struct memfp *mp)
{
	return mp->pos - mp->buf;
}

static inline void mseek(struct memfp *mp, long offset, int whence)
{
	switch (whence) {
	case SEEK_SET:
		mp->pos = mp->buf + offset;
		break;
	case SEEK_CUR:
		mp->pos += offset;
		break;
	case SEEK_END:
		mp->pos = mp->end + offset;
		break;
	}
}

static inline void memfp_close(struct memfp *mp)
{
	mp->buf = NULL;
	mp->pos = NULL;
	mp->end = NULL;
}

#endif /* MEMFP_H */
