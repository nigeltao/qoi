#ifndef QOILE_H
#define QOILE_H

#ifdef __cplusplus
extern "C" {
#endif

void *qoile_encode(const void *data, int w, int h, int channels, int *out_len);

void *qoile_decode(const void *data, int size, int *out_w, int *out_h, int channels);

#ifdef __cplusplus
}
#endif
#endif // QOILE_H


// -----------------------------------------------------------------------------
// Implementation

#ifdef QOILE_IMPLEMENTATION
#include <stdint.h>
#include <stdlib.h>

#ifndef QOI_MALLOC
	#define QOI_MALLOC(sz) malloc(sz)
	#define QOI_FREE(p)    free(p)
#endif

#define QOILE_INDEX   0x00 // xxxxxx00
#define QOILE_RUN_8   0x02 // xxxxx010
#define QOILE_RUN_16  0x06 // xxxxx110
#define QOILE_DIFF_8  0x01 // xxxxxx01
#define QOILE_DIFF_16 0x03 // xxxxx011
#define QOILE_DIFF_24 0x07 // xxxx0111
#define QOILE_COLOR   0x0F // xxxx1111

#define QOILE_MASK_2  0x03 // 00000011
#define QOILE_MASK_3  0x07 // 00000111
#define QOILE_MASK_4  0x0F // 00001111

static inline uint32_t peek_u32le(const uint8_t* p) {
	return ((uint32_t)(p[0]) << 0) | ((uint32_t)(p[1]) << 8) | ((uint32_t)(p[2]) << 16) | ((uint32_t)(p[3]) << 24);
}

static inline void poke_u8(uint8_t* p, uint8_t x) {
	p[0] = x;
}

static inline void poke_u16le(uint8_t* p, uint16_t x) {
	p[0] = (uint8_t)(x >> 0);
	p[1] = (uint8_t)(x >> 8);
}

static inline void poke_u24le(uint8_t* p, uint32_t x) {
	p[0] = (uint8_t)(x >> 0);
	p[1] = (uint8_t)(x >> 8);
	p[2] = (uint8_t)(x >> 16);
}

void *qoile_encode(const void *data, int w, int h, int channels, int *out_len) {
	if (
		data == NULL || out_len == NULL ||
		w <= 0 || w >= (1 << 16) ||
		h <= 0 || h >= (1 << 16) ||
		channels < 3 || channels > 4
	) {
		return NULL;
	}

	int max_size = w * h * (channels + 1) + QOI_HEADER_SIZE + QOI_PADDING;
	int p = 0;
	unsigned char *bytes = QOI_MALLOC(max_size);
	if (!bytes) {
		return NULL;
	}

	qoi_write_32(bytes, &p, QOI_MAGIC);
	qoi_write_16(bytes, &p, w);
	qoi_write_16(bytes, &p, h);
	qoi_write_32(bytes, &p, 0); // size, will be set later

	const unsigned char *pixels = (const unsigned char *)data;

	qoi_rgba_t index[64] = {0};

	int run = 0;
	qoi_rgba_t px_prev = {.rgba = {.r = 0, .g = 0, .b = 0, .a = 255}};
	qoi_rgba_t px = px_prev;

	int px_len = w * h * channels;
	int px_end = px_len - channels;
	for (int px_pos = 0; px_pos < px_len; px_pos += channels) {
		if (channels == 4) {
			px = *(qoi_rgba_t *)(pixels + px_pos);
		}
		else {
			px.rgba.r = pixels[px_pos];
			px.rgba.g = pixels[px_pos+1];
			px.rgba.b = pixels[px_pos+2];
		}

		if (px.v == px_prev.v) {
			run++;
		}

		if (run > 0 && (run == 0x2020 || px.v != px_prev.v || px_pos == px_end)) {
			if (run < 33) {
				run -= 1;
				poke_u8(bytes+p, QOILE_RUN_8 | (run << 3));
				p += 1;
			}
			else {
				run -= 33;
				poke_u16le(bytes+p, QOILE_RUN_16 | (run << 3));
				p += 2;
			}
			run = 0;
		}

		if (px.v != px_prev.v) {
			int index_pos = QOI_COLOR_HASH(px) % 64;

			if (index[index_pos].v == px.v) {
				poke_u8(bytes+p, QOILE_INDEX | (index_pos << 3));
				p += 1;
			}
			else {
				index[index_pos] = px;

				int vr = px.rgba.r - px_prev.rgba.r;
				int vg = px.rgba.g - px_prev.rgba.g;
				int vb = px.rgba.b - px_prev.rgba.b;
				int va = px.rgba.a - px_prev.rgba.a;

				if (
					vr > -16 && vr < 17 && vg > -16 && vg < 17 && 
					vb > -16 && vb < 17 && va > -16 && va < 17
				) {
					if (
						va == 0 && vr > -2 && vr < 3 &&
						vg > -2 && vg < 3 && vb > -2 && vb < 3
					) {
						poke_u8(bytes+p, QOILE_DIFF_8 | ((vr + 1) << 2) | ((vg + 1) << 4) | ((vb + 1) << 6));
						p += 1;
					}
					else if (
						va == 0 && vr > -16 && vr < 17 && 
						vg > -8 && vg < 9 && vb > -8 && vb < 9
					) {
						poke_u16le(bytes+p, QOILE_DIFF_16 | ((vr + 15) << 3) | ((vg + 7) << 8) | ((vb + 7) << 12));
						p += 2;
					}
					else {
						poke_u24le(bytes+p, QOILE_DIFF_24 | ((vr + 15) << 4) | ((vg + 15) << 9) | ((vb + 15) << 14) | ((va + 15) << 19));
						p += 3;
					}
				}
				else {
					bytes[p++] = QOILE_COLOR | (vr?0x10:0)|(vg?0x20:0)|(vb?0x40:0)|(va?0x80:0);
					if (vr) { bytes[p++] = px.rgba.r; }
					if (vg) { bytes[p++] = px.rgba.g; }
					if (vb) { bytes[p++] = px.rgba.b; }
					if (va) { bytes[p++] = px.rgba.a; }
				}
			}
		}
		px_prev = px;
	}

	for (int i = 0; i < QOI_PADDING; i++) {
		bytes[p++] = 0;
	}

	int data_len = p - QOI_HEADER_SIZE;
	*out_len = p;

	p = 8;
	qoi_write_32(bytes, &p, data_len);
	return bytes;
}

void *qoile_decode(const void *data, int size, int *out_w, int *out_h, int channels) {
	if (channels < 3 || channels > 4 || size < QOI_HEADER_SIZE) {
		return NULL;
	}

	const unsigned char *bytes = (const unsigned char *)data;
	int p = 0;

	int magic = qoi_read_32(bytes, &p);
	int w = qoi_read_16(bytes, &p);
	int h = qoi_read_16(bytes, &p);
	int data_len = qoi_read_32(bytes, &p);

	if (
		w == 0 || h == 0 || magic != QOI_MAGIC || 
		size != data_len + QOI_HEADER_SIZE
	) {
		return NULL;
	}

	int px_len = w * h * channels;
	unsigned char *pixels = QOI_MALLOC(px_len);
	if (!pixels) {
		return NULL;
	}

	qoi_rgba_t px = {.rgba = {.r = 0, .g = 0, .b = 0, .a = 255}};
	qoi_rgba_t index[64] = {0};

	int run = 0;
	int chunks_len = size - QOI_PADDING;
	for (int px_pos = 0; px_pos < px_len; px_pos += channels) {
		if (run > 0) {
			run--;
		}
		else if (p < chunks_len) {
			uint32_t b = peek_u32le(bytes + p);

			if ((b & QOILE_MASK_2) == QOILE_INDEX) {
				px = index[(b >> 2) & 63];
				p += 1;
			}
			else if ((b & QOILE_MASK_3) == QOILE_RUN_8) {
				run = ((b >> 3) & 0x1F);
				p += 1;
			}
			else if ((b & QOILE_MASK_3) == QOILE_RUN_16) {
				run = ((b >> 3) & 0x1FFF);
				p += 2;
			}
			else if ((b & QOILE_MASK_2) == QOILE_DIFF_8) {
				px.rgba.r += ((b >> 2) & 0x03) - 1;
				px.rgba.g += ((b >> 4) & 0x03) - 1;
				px.rgba.b += ((b >> 6) & 0x03) - 1;
				p += 1;
			}
			else if ((b & QOILE_MASK_3) == QOILE_DIFF_16) {
				px.rgba.r += ((b >>  3) & 0x1F) - 15;
				px.rgba.g += ((b >>  8) & 0x0F) - 7;
				px.rgba.b += ((b >> 12) & 0x0F) - 7;
				p += 2;
			}
			else if ((b & QOILE_MASK_4) == QOILE_DIFF_24) {
				px.rgba.r += ((b >>  4) & 0x1F) - 15;
				px.rgba.g += ((b >>  9) & 0x1F) - 15;
				px.rgba.b += ((b >> 14) & 0x1F) - 15;
				px.rgba.a += ((b >> 19) & 0x1F) - 15;
				p += 3;
			}
			else if ((b & QOILE_MASK_4) == QOILE_COLOR) {
				p += 1;
				if (b & 0x10) { px.rgba.r = bytes[p++]; }
				if (b & 0x20) { px.rgba.g = bytes[p++]; }
				if (b & 0x40) { px.rgba.b = bytes[p++]; }
				if (b & 0x80) { px.rgba.a = bytes[p++]; }
			}

			index[QOI_COLOR_HASH(px) % 64] = px;
		}

		if (channels == 4) { 
			*(qoi_rgba_t*)(pixels + px_pos) = px;
		}
		else {
			pixels[px_pos] = px.rgba.r;
			pixels[px_pos+1] = px.rgba.g;
			pixels[px_pos+2] = px.rgba.b;
		}
	}

	*out_w = w;
	*out_h = h;
	return pixels;
}

#endif // QOILE_IMPLEMENTATION
