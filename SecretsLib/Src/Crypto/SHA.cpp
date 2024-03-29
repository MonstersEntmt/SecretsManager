#include "Crypto/Crypto.h"

#include <cstring>

#include <bit>

namespace Crypto
{
	struct SHAState
	{
		ESHAFunction SHAFunction;

		size_t   MessageSize;
		uint8_t  BufferSize;
		uint32_t State[16];
		uint8_t  Buffer[128];
	};

	static bool SHA1_Init(SHAState* state)
	{
		state->State[0] = 0x67452301;
		state->State[1] = 0xEFCDAB89;
		state->State[2] = 0x98BADCFE;
		state->State[3] = 0x10325476;
		state->State[4] = 0xC3D2E1F0;
		return true;
	}

	static void SHA1_Chunk(SHAState* state, const uint8_t* chunk)
	{
		uint32_t w[80];
		for (size_t i = 0; i < 16; ++i)
		{
			w[i] = chunk[i * 4] << 24 |
				   chunk[i * 4 + 1] << 16 |
				   chunk[i * 4 + 2] << 8 |
				   chunk[i * 4 + 3];
		}
		for (size_t i = 16; i < 80; ++i)
			w[i] = std::rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

		uint32_t a = state->State[0];
		uint32_t b = state->State[1];
		uint32_t c = state->State[2];
		uint32_t d = state->State[3];
		uint32_t e = state->State[4];
		for (size_t i = 0; i < 20; ++i)
		{
			uint32_t temp = std::rotl(a, 5) + e + w[i] + ((b & c) | ((~b) & d)) + 0x5A827999;
			e             = d;
			d             = c;
			c             = std::rotl(b, 30);
			b             = a;
			a             = temp;
		}
		for (size_t i = 20; i < 40; ++i)
		{
			uint32_t temp = std::rotl(a, 5) + e + w[i] + (b ^ c ^ d) + 0x6ED9EBA1;
			e             = d;
			d             = c;
			c             = std::rotl(b, 30);
			b             = a;
			a             = temp;
		}
		for (size_t i = 40; i < 60; ++i)
		{
			uint32_t temp = std::rotl(a, 5) + e + w[i] + ((b & c) | (b & d) | (c & d)) + 0x8F1BBCDC;
			e             = d;
			d             = c;
			c             = std::rotl(b, 30);
			b             = a;
			a             = temp;
		}
		for (size_t i = 60; i < 80; ++i)
		{
			uint32_t temp = std::rotl(a, 5) + e + w[i] + (b ^ c ^ d) + 0xCA62C1D6;
			e             = d;
			d             = c;
			c             = std::rotl(b, 30);
			b             = a;
			a             = temp;
		}

		state->State[0]    += a;
		state->State[1]    += b;
		state->State[2]    += c;
		state->State[3]    += d;
		state->State[4]    += e;
		state->MessageSize += 64;
	}

	static bool SHA1_Data(SHAState* state, const uint8_t* data, size_t dataSize)
	{
		if (dataSize < 64 - state->BufferSize)
		{
			memcpy(state->Buffer + state->BufferSize, data, dataSize);
			state->BufferSize += (uint8_t) dataSize;
			return true;
		}

		uint8_t chunk[64];
		memcpy(chunk, state->Buffer, state->BufferSize);
		memcpy(chunk + state->BufferSize, data, 64 - state->BufferSize);
		size_t offset     = 64 - state->BufferSize;
		state->BufferSize = 0;
		SHA1_Chunk(state, chunk);
		while (offset < dataSize)
		{
			size_t end = offset + 64;
			if (end > dataSize)
			{
				memcpy(state->Buffer, data + offset, dataSize - offset);
				state->BufferSize = (uint8_t) (dataSize - offset);
				break;
			}

			memcpy(chunk, data + offset, 64);
			SHA1_Chunk(state, chunk);
			offset = end;
		}
		return true;
	}

	static bool SHA1_Final(SHAState* state, uint8_t* digest)
	{
		uint64_t ml = (state->MessageSize + state->BufferSize) * 8;

		state->Buffer[state->BufferSize++] = 0x80;
		if (state->BufferSize > 56)
		{
			memset(state->Buffer + state->BufferSize, 0, 64 - state->BufferSize);
			SHA1_Chunk(state, state->Buffer);
			state->BufferSize = 0;
		}
		memset(state->Buffer + state->BufferSize, 0, 56 - state->BufferSize);
		state->Buffer[56] = (ml >> 56) & 0xFF;
		state->Buffer[57] = (ml >> 48) & 0xFF;
		state->Buffer[58] = (ml >> 40) & 0xFF;
		state->Buffer[59] = (ml >> 32) & 0xFF;
		state->Buffer[60] = (ml >> 24) & 0xFF;
		state->Buffer[61] = (ml >> 16) & 0xFF;
		state->Buffer[62] = (ml >> 8) & 0xFF;
		state->Buffer[63] = ml & 0xFF;
		SHA1_Chunk(state, state->Buffer);
		memset(state->Buffer, 0, 64);
		for (size_t i = 0; i < 5; ++i)
		{
			digest[i * 4]     = (state->State[i] >> 24) & 0xFF;
			digest[i * 4 + 1] = (state->State[i] >> 16) & 0xFF;
			digest[i * 4 + 2] = (state->State[i] >> 8) & 0xFF;
			digest[i * 4 + 3] = state->State[i] & 0xFF;
		}
		return true;
	}

	static void SHA2_32Chunk(SHAState* state, const uint8_t* chunk)
	{
		static constexpr uint32_t c_K[] = { 0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2 };

		uint32_t w[64];
		for (size_t i = 0; i < 16; ++i)
		{
			w[i] = chunk[i * 4] << 24 |
				   chunk[i * 4 + 1] << 16 |
				   chunk[i * 4 + 2] << 8 |
				   chunk[i * 4 + 3];
		}
		for (size_t i = 16; i < 64; ++i)
		{
			uint32_t s0 = std::rotr(w[i - 15], 7) ^ std::rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
			uint32_t s1 = std::rotr(w[i - 2], 17) ^ std::rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
			w[i]        = w[i - 16] + s0 + w[i - 7] + s1;
		}

		uint32_t a = state->State[0];
		uint32_t b = state->State[1];
		uint32_t c = state->State[2];
		uint32_t d = state->State[3];
		uint32_t e = state->State[4];
		uint32_t f = state->State[5];
		uint32_t g = state->State[6];
		uint32_t h = state->State[7];
		for (size_t i = 0; i < 64; ++i)
		{
			uint32_t S1    = std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
			uint32_t ch    = (e & f) ^ ((~e) & g);
			uint32_t temp1 = h + S1 + ch + c_K[i] + w[i];
			uint32_t S0    = std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
			uint32_t maj   = (a & b) ^ (a & c) ^ (b & c);
			uint32_t temp2 = S0 + maj;

			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}

		state->State[0]    += a;
		state->State[1]    += b;
		state->State[2]    += c;
		state->State[3]    += d;
		state->State[4]    += e;
		state->State[5]    += f;
		state->State[6]    += g;
		state->State[7]    += h;
		state->MessageSize += 64;
	}

	static void SHA2_64Chunk(SHAState* state, const uint8_t* chunk)
	{
		static constexpr uint64_t c_K[] = { 0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC, 0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118, 0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2, 0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694, 0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65, 0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5, 0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4, 0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70, 0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF, 0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B, 0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30, 0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8, 0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8, 0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3, 0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC, 0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B, 0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178, 0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B, 0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C, 0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817 };

		uint64_t w[80];
		for (size_t i = 0; i < 16; ++i)
		{
			w[i] = uint64_t(chunk[i * 8]) << 56 |
				   uint64_t(chunk[i * 8 + 1]) << 48 |
				   uint64_t(chunk[i * 8 + 2]) << 40 |
				   uint64_t(chunk[i * 8 + 3]) << 32 |
				   uint64_t(chunk[i * 8 + 4]) << 24 |
				   uint64_t(chunk[i * 8 + 5]) << 16 |
				   uint64_t(chunk[i * 8 + 6]) << 8 |
				   uint64_t(chunk[i * 8 + 7]);
		}
		for (size_t i = 16; i < 80; ++i)
		{
			uint64_t s0 = std::rotr(w[i - 15], 1) ^ std::rotr(w[i - 15], 8) ^ (w[i - 15] >> 7);
			uint64_t s1 = std::rotr(w[i - 2], 19) ^ std::rotr(w[i - 2], 61) ^ (w[i - 2] >> 6);
			w[i]        = w[i - 16] + s0 + w[i - 7] + s1;
		}

		uint64_t* state64 = (uint64_t*) state->State;
		uint64_t  a       = state64[0];
		uint64_t  b       = state64[1];
		uint64_t  c       = state64[2];
		uint64_t  d       = state64[3];
		uint64_t  e       = state64[4];
		uint64_t  f       = state64[5];
		uint64_t  g       = state64[6];
		uint64_t  h       = state64[7];
		for (size_t i = 0; i < 80; ++i)
		{
			uint64_t S1    = std::rotr(e, 14) ^ std::rotr(e, 18) ^ std::rotr(e, 41);
			uint64_t ch    = (e & f) ^ ((~e) & g);
			uint64_t temp1 = h + S1 + ch + c_K[i] + w[i];
			uint64_t S0    = std::rotr(a, 28) ^ std::rotr(a, 34) ^ std::rotr(a, 39);
			uint64_t maj   = (a & b) ^ (a & c) ^ (b & c);
			uint64_t temp2 = S0 + maj;

			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}
		state64[0]         += a;
		state64[1]         += b;
		state64[2]         += c;
		state64[3]         += d;
		state64[4]         += e;
		state64[5]         += f;
		state64[6]         += g;
		state64[7]         += h;
		state->MessageSize += 128;
	}

	static bool SHA2_224Init(SHAState* state)
	{
		state->State[0] = 0xC1059ED8;
		state->State[1] = 0x367CD507;
		state->State[2] = 0x3070DD17;
		state->State[3] = 0xF70E5939;
		state->State[4] = 0xFFC00B31;
		state->State[5] = 0x68581511;
		state->State[6] = 0x64F98FA7;
		state->State[7] = 0xBEFA4FA4;
		return true;
	}

	static bool SHA2_256Init(SHAState* state)
	{
		state->State[0] = 0x6A09E667;
		state->State[1] = 0xBB67AE85;
		state->State[2] = 0x3C6EF372;
		state->State[3] = 0xA54FF53A;
		state->State[4] = 0x510E527F;
		state->State[5] = 0x9B05688C;
		state->State[6] = 0x1F83D9AB;
		state->State[7] = 0x5BE0CD19;
		return true;
	}

	static bool SHA2_384Init(SHAState* state)
	{
		uint64_t* state64 = (uint64_t*) state->State;
		state64[0]        = 0xCBBB9D5DC1059ED8;
		state64[1]        = 0x629A292A367CD507;
		state64[2]        = 0x9159015A3070DD17;
		state64[3]        = 0x152FECD8F70E5939;
		state64[4]        = 0x67332667FFC00B31;
		state64[5]        = 0x8EB44A8768581511;
		state64[6]        = 0xDB0C2E0D64F98FA7;
		state64[7]        = 0x47B5481DBEFA4FA4;
		return true;
	}

	static bool SHA2_512Init(SHAState* state)
	{
		uint64_t* state64 = (uint64_t*) state->State;
		state64[0]        = 0x6A09E667F3BCC908;
		state64[1]        = 0xBB67AE8584CAA73B;
		state64[2]        = 0x3C6EF372FE94F82B;
		state64[3]        = 0xA54FF53A5F1D36F1;
		state64[4]        = 0x510E527FADE682D1;
		state64[5]        = 0x9B05688C2B3E6C1F;
		state64[6]        = 0x1F83D9ABFB41BD6B;
		state64[7]        = 0x5BE0CD19137E2179;
		return true;
	}

	static bool SHA2_32Data(SHAState* state, const uint8_t* data, size_t dataSize)
	{
		if (dataSize < 64 - state->BufferSize)
		{
			memcpy(state->Buffer + state->BufferSize, data, dataSize);
			state->BufferSize += (uint8_t) dataSize;
			return true;
		}

		uint8_t chunk[64];
		memcpy(chunk, state->Buffer, state->BufferSize);
		memcpy(chunk + state->BufferSize, data, 64 - state->BufferSize);
		size_t offset     = 64 - state->BufferSize;
		state->BufferSize = 0;
		SHA2_32Chunk(state, chunk);
		while (offset < dataSize)
		{
			size_t end = offset + 64;
			if (end > dataSize)
			{
				memcpy(state->Buffer, data + offset, dataSize - offset);
				state->BufferSize = (uint8_t) (dataSize - offset);
				break;
			}

			memcpy(chunk, data + offset, 64);
			SHA2_32Chunk(state, chunk);
			offset = end;
		}
		return true;
	}

	static bool SHA2_64Data(SHAState* state, const uint8_t* data, size_t dataSize)
	{
		if (dataSize < 128 - state->BufferSize)
		{
			memcpy(state->Buffer + state->BufferSize, data, dataSize);
			state->BufferSize += (uint8_t) dataSize;
			return true;
		}

		uint8_t chunk[128];
		memcpy(chunk, state->Buffer, state->BufferSize);
		memcpy(chunk + state->BufferSize, data, 128 - state->BufferSize);
		size_t offset     = 128 - state->BufferSize;
		state->BufferSize = 0;
		SHA2_64Chunk(state, chunk);
		while (offset < dataSize)
		{
			size_t end = offset + 128;
			if (end > dataSize)
			{
				memcpy(state->Buffer, data + offset, dataSize - offset);
				state->BufferSize = (uint8_t) (dataSize - offset);
				break;
			}

			memcpy(chunk, data + offset, 128);
			SHA2_64Chunk(state, chunk);
			offset = end;
		}
		return true;
	}

	static bool SHA2_32Final(SHAState* state, uint8_t* digest)
	{
		uint64_t ml = (state->MessageSize + state->BufferSize) * 8;

		state->Buffer[state->BufferSize++] = 0x80;
		if (state->BufferSize > 56)
		{
			memset(state->Buffer + state->BufferSize, 0, 64 - state->BufferSize);
			SHA2_32Chunk(state, state->Buffer);
			state->BufferSize = 0;
		}
		memset(state->Buffer + state->BufferSize, 0, 56 - state->BufferSize);
		state->Buffer[56] = (ml >> 56) & 0xFF;
		state->Buffer[57] = (ml >> 48) & 0xFF;
		state->Buffer[58] = (ml >> 40) & 0xFF;
		state->Buffer[59] = (ml >> 32) & 0xFF;
		state->Buffer[60] = (ml >> 24) & 0xFF;
		state->Buffer[61] = (ml >> 16) & 0xFF;
		state->Buffer[62] = (ml >> 8) & 0xFF;
		state->Buffer[63] = ml & 0xFF;
		SHA2_32Chunk(state, state->Buffer);
		memset(state->Buffer, 0, 64);
		size_t digestSize = 0;
		SHA_DigestSize(state, &digestSize);
		for (size_t i = 0; i < digestSize / 4; ++i)
		{
			digest[i * 4]     = (state->State[i] >> 24) & 0xFF;
			digest[i * 4 + 1] = (state->State[i] >> 16) & 0xFF;
			digest[i * 4 + 2] = (state->State[i] >> 8) & 0xFF;
			digest[i * 4 + 3] = state->State[i] & 0xFF;
		}
		return true;
	}

	static bool SHA2_64Final(SHAState* state, uint8_t* digest)
	{
		uint64_t mlUpper = (state->MessageSize + state->BufferSize) >> 61;
		uint64_t mlLower = (state->MessageSize + state->BufferSize) << 3;

		state->Buffer[state->BufferSize++] = 0x80;
		if (state->BufferSize > 112)
		{
			memset(state->Buffer + state->BufferSize, 0, 128 - state->BufferSize);
			SHA2_64Chunk(state, state->Buffer);
			state->BufferSize = 0;
		}
		memset(state->Buffer + state->BufferSize, 0, 112 - state->BufferSize);
		state->Buffer[112] = (mlUpper >> 56) & 0xFF;
		state->Buffer[113] = (mlUpper >> 48) & 0xFF;
		state->Buffer[114] = (mlUpper >> 40) & 0xFF;
		state->Buffer[115] = (mlUpper >> 32) & 0xFF;
		state->Buffer[116] = (mlUpper >> 24) & 0xFF;
		state->Buffer[117] = (mlUpper >> 16) & 0xFF;
		state->Buffer[118] = (mlUpper >> 8) & 0xFF;
		state->Buffer[119] = mlUpper & 0xFF;
		state->Buffer[120] = (mlLower >> 56) & 0xFF;
		state->Buffer[121] = (mlLower >> 48) & 0xFF;
		state->Buffer[122] = (mlLower >> 40) & 0xFF;
		state->Buffer[123] = (mlLower >> 32) & 0xFF;
		state->Buffer[124] = (mlLower >> 24) & 0xFF;
		state->Buffer[125] = (mlLower >> 16) & 0xFF;
		state->Buffer[126] = (mlLower >> 8) & 0xFF;
		state->Buffer[127] = mlLower & 0xFF;
		SHA2_64Chunk(state, state->Buffer);
		memset(state->Buffer, 0, 128);
		size_t digestSize = 0;
		SHA_DigestSize(state, &digestSize);
		uint64_t* state64 = (uint64_t*) state->State;
		for (size_t i = 0; i < digestSize / 8; ++i)
		{
			digest[i * 8]     = (state64[i] >> 56) & 0xFF;
			digest[i * 8 + 1] = (state64[i] >> 48) & 0xFF;
			digest[i * 8 + 2] = (state64[i] >> 40) & 0xFF;
			digest[i * 8 + 3] = (state64[i] >> 32) & 0xFF;
			digest[i * 8 + 4] = (state64[i] >> 24) & 0xFF;
			digest[i * 8 + 5] = (state64[i] >> 16) & 0xFF;
			digest[i * 8 + 6] = (state64[i] >> 8) & 0xFF;
			digest[i * 8 + 7] = state64[i] & 0xFF;
		}
		return true;
	}

	static bool SHA3_224Init(SHAState* state)
	{
		return false;
	}

	static bool SHA3_256Init(SHAState* state)
	{
		return false;
	}

	static bool SHA3_384Init(SHAState* state)
	{
		return false;
	}

	static bool SHA3_512Init(SHAState* state)
	{
		return false;
	}

	static bool SHA3_32Data(SHAState* state, const uint8_t* data, size_t dataSize)
	{
		return false;
	}

	static bool SHA3_64Data(SHAState* state, const uint8_t* data, size_t dataSize)
	{
		return false;
	}

	static bool SHA3_32Final(SHAState* state, uint8_t* digest)
	{
		return false;
	}

	static bool SHA3_64Final(SHAState* state, uint8_t* digest)
	{
		return false;
	}

	bool SHA_Init(void** state, ESHAFunction shaFunction)
	{
		if (!state)
			return false;
		switch (shaFunction)
		{
		case ESHAFunction::SHA1:
		case ESHAFunction::SHA2_224:
		case ESHAFunction::SHA2_256:
		case ESHAFunction::SHA2_384:
		case ESHAFunction::SHA2_512:
		case ESHAFunction::SHA3_224:
		case ESHAFunction::SHA3_256:
		case ESHAFunction::SHA3_384:
		case ESHAFunction::SHA3_512: break;
		case ESHAFunction::SHA2: shaFunction = ESHAFunction::SHA2_256; break;
		case ESHAFunction::SHA3: shaFunction = ESHAFunction::SHA3_256; break;
		default: return false;
		}

		SHAState* shaState    = new SHAState();
		shaState->SHAFunction = shaFunction;
		shaState->MessageSize = 0;
		shaState->BufferSize  = 0;
		memset(shaState->State, 0, sizeof(shaState->State));
		memset(shaState->Buffer, 0, sizeof(shaState->Buffer));
		*state = shaState;
		switch (shaState->SHAFunction)
		{
		case ESHAFunction::SHA1: return SHA1_Init(shaState);
		case ESHAFunction::SHA2_224: return SHA2_224Init(shaState);
		case ESHAFunction::SHA2_256: return SHA2_256Init(shaState);
		case ESHAFunction::SHA2_384: return SHA2_384Init(shaState);
		case ESHAFunction::SHA2_512: return SHA2_512Init(shaState);
		case ESHAFunction::SHA3_224: return SHA3_224Init(shaState);
		case ESHAFunction::SHA3_256: return SHA3_256Init(shaState);
		case ESHAFunction::SHA3_384: return SHA3_384Init(shaState);
		case ESHAFunction::SHA3_512: return SHA3_512Init(shaState);
		}
		return true;
	}

	bool SHA_Reset(void* state)
	{
		if (!state)
			return false;

		auto shaState         = (SHAState*) state;
		shaState->MessageSize = 0;
		shaState->BufferSize  = 0;
		memset(shaState->State, 0, sizeof(shaState->State));
		memset(shaState->Buffer, 0, sizeof(shaState->Buffer));
		switch (shaState->SHAFunction)
		{
		case ESHAFunction::SHA1: return SHA1_Init(shaState);
		case ESHAFunction::SHA2_224: return SHA2_224Init(shaState);
		case ESHAFunction::SHA2_256: return SHA2_256Init(shaState);
		case ESHAFunction::SHA2_384: return SHA2_384Init(shaState);
		case ESHAFunction::SHA2_512: return SHA2_512Init(shaState);
		case ESHAFunction::SHA3_224: return SHA3_224Init(shaState);
		case ESHAFunction::SHA3_256: return SHA3_256Init(shaState);
		case ESHAFunction::SHA3_384: return SHA3_384Init(shaState);
		case ESHAFunction::SHA3_512: return SHA3_512Init(shaState);
		}
		return true;
	}

	bool SHA_Destroy(void* state)
	{
		if (!state)
			return false;
		delete (SHAState*) state;
		return true;
	}

	bool SHA_DigestSize(void* state, size_t* digestSize)
	{
		if (!state || !digestSize)
			return false;
		auto shaState = (SHAState*) state;
		switch (shaState->SHAFunction)
		{
		case ESHAFunction::SHA1: *digestSize = 20; break;
		case ESHAFunction::SHA2_224: *digestSize = 28; break;
		case ESHAFunction::SHA2_256: *digestSize = 32; break;
		case ESHAFunction::SHA2_384: *digestSize = 48; break;
		case ESHAFunction::SHA2_512: *digestSize = 64; break;
		case ESHAFunction::SHA3_224: *digestSize = 28; break;
		case ESHAFunction::SHA3_256: *digestSize = 32; break;
		case ESHAFunction::SHA3_384: *digestSize = 48; break;
		case ESHAFunction::SHA3_512: *digestSize = 64; break;
		default: return false;
		}
		return true;
	}

	bool SHA_BlockSize(void* state, size_t* blockSize)
	{
		if (!state || !blockSize)
			return false;
		auto shaState = (SHAState*) state;
		switch (shaState->SHAFunction)
		{
		case ESHAFunction::SHA1: *blockSize = 64; break;
		case ESHAFunction::SHA2_224: *blockSize = 64; break;
		case ESHAFunction::SHA2_256: *blockSize = 64; break;
		case ESHAFunction::SHA2_384: *blockSize = 128; break;
		case ESHAFunction::SHA2_512: *blockSize = 128; break;
		case ESHAFunction::SHA3_224: *blockSize = 64; break;
		case ESHAFunction::SHA3_256: *blockSize = 64; break;
		case ESHAFunction::SHA3_384: *blockSize = 128; break;
		case ESHAFunction::SHA3_512: *blockSize = 128; break;
		default: return false;
		}
		return true;
	}

	bool SHA_Data(void* state, const void* data, size_t dataSize)
	{
		if (!state || (dataSize > 0 && !data))
			return false;
		auto shaState = (SHAState*) state;
		switch (shaState->SHAFunction)
		{
		case ESHAFunction::SHA1: return SHA1_Data(shaState, (const uint8_t*) data, dataSize);
		case ESHAFunction::SHA2_224:
		case ESHAFunction::SHA2_256: return SHA2_32Data(shaState, (const uint8_t*) data, dataSize);
		case ESHAFunction::SHA2_384:
		case ESHAFunction::SHA2_512: return SHA2_64Data(shaState, (const uint8_t*) data, dataSize);
		case ESHAFunction::SHA3_224:
		case ESHAFunction::SHA3_256: return SHA3_32Data(shaState, (const uint8_t*) data, dataSize);
		case ESHAFunction::SHA3_384:
		case ESHAFunction::SHA3_512: return SHA3_64Data(shaState, (const uint8_t*) data, dataSize);
		}
		return true;
	}

	bool SHA_Final(void* state, void* digest, size_t* digestSize, bool reset)
	{
		if (!state || !digest || !digestSize)
			return false;

		auto shaState = (SHAState*) state;
		bool result   = false;
		switch (shaState->SHAFunction)
		{
		case ESHAFunction::SHA1: result = *digestSize >= 20 && SHA1_Final(shaState, (uint8_t*) digest); break;
		case ESHAFunction::SHA2_224: result = *digestSize >= 28 && SHA2_32Final(shaState, (uint8_t*) digest); break;
		case ESHAFunction::SHA2_256: result = *digestSize >= 32 && SHA2_32Final(shaState, (uint8_t*) digest); break;
		case ESHAFunction::SHA2_384: result = *digestSize >= 48 && SHA2_64Final(shaState, (uint8_t*) digest); break;
		case ESHAFunction::SHA2_512: result = *digestSize >= 64 && SHA2_64Final(shaState, (uint8_t*) digest); break;
		case ESHAFunction::SHA3_224: result = *digestSize >= 28 && SHA3_32Final(shaState, (uint8_t*) digest); break;
		case ESHAFunction::SHA3_256: result = *digestSize >= 32 && SHA3_32Final(shaState, (uint8_t*) digest); break;
		case ESHAFunction::SHA3_384: result = *digestSize >= 48 && SHA3_64Final(shaState, (uint8_t*) digest); break;
		case ESHAFunction::SHA3_512: result = *digestSize >= 64 && SHA3_64Final(shaState, (uint8_t*) digest); break;
		}
	}
} // namespace Crypto