#include "Crypto/Crypto.h"
#include "Utils/Time.h"

#include <cstring>

namespace Crypto
{
	struct HashState
	{
		EHashFunction HashFunction;
		void*         SubState;
	};

	bool Hash_Init(void** state, EHashFunction hashFunction)
	{
		if (!state)
			return false;

		void* subState = nullptr;
		switch (hashFunction)
		{
		case EHashFunction::SHA1:
			if (!SHA_Init(&subState, ESHAFunction::SHA1))
				return false;
			break;
		case EHashFunction::SHA2_224:
			if (!SHA_Init(&subState, ESHAFunction::SHA2_224))
				return false;
			break;
		case EHashFunction::SHA2_256:
			if (!SHA_Init(&subState, ESHAFunction::SHA2_256))
				return false;
			break;
		case EHashFunction::SHA2_384:
			if (!SHA_Init(&subState, ESHAFunction::SHA2_384))
				return false;
			break;
		case EHashFunction::SHA2_512:
			if (!SHA_Init(&subState, ESHAFunction::SHA2_512))
				return false;
			break;
		default:
			return false;
		}

		HashState* hashState    = new HashState();
		hashState->HashFunction = hashFunction;
		hashState->SubState     = subState;
		*state                  = hashState;
		return true;
	}

	bool Hash_Reset(void* state)
	{
		if (!state)
			return false;
		auto hashState = (HashState*) state;
		switch (hashState->HashFunction)
		{
		case EHashFunction::SHA1:
		case EHashFunction::SHA2_224:
		case EHashFunction::SHA2_256:
		case EHashFunction::SHA2_384:
		case EHashFunction::SHA2_512: return SHA_Reset(hashState->SubState); break;
		default: return false;
		}
	}

	bool Hash_Destroy(void* state)
	{
		if (!state)
			return false;
		auto hashState = (HashState*) state;
		switch (hashState->HashFunction)
		{
		case EHashFunction::SHA1:
		case EHashFunction::SHA2_224:
		case EHashFunction::SHA2_256:
		case EHashFunction::SHA2_384:
		case EHashFunction::SHA2_512: SHA_Destroy(hashState->SubState); break;
		}
		delete hashState;
		return true;
	}

	bool Hash_DigestSize(void* state, size_t* digestSize)
	{
		if (!state)
			return false;
		auto hashState = (HashState*) state;
		switch (hashState->HashFunction)
		{
		case EHashFunction::SHA1:
		case EHashFunction::SHA2_224:
		case EHashFunction::SHA2_256:
		case EHashFunction::SHA2_384:
		case EHashFunction::SHA2_512: return SHA_DigestSize(hashState->SubState, digestSize); break;
		default:
			if (digestSize)
				*digestSize = 0;
			return false;
		}
	}

	bool Hash_BlockSize(void* state, size_t* blockSize)
	{
		if (!state)
			return false;
		auto hashState = (HashState*) state;
		switch (hashState->HashFunction)
		{
		case EHashFunction::SHA1:
		case EHashFunction::SHA2_224:
		case EHashFunction::SHA2_256:
		case EHashFunction::SHA2_384:
		case EHashFunction::SHA2_512: return SHA_BlockSize(hashState->SubState, blockSize); break;
		default:
			if (blockSize)
				*blockSize = 0;
			return false;
		}
	}

	bool Hash_Data(void* state, const void* data, size_t dataSize)
	{
		if (!state)
			return false;
		auto hashState = (HashState*) state;
		switch (hashState->HashFunction)
		{
		case EHashFunction::SHA1:
		case EHashFunction::SHA2_224:
		case EHashFunction::SHA2_256:
		case EHashFunction::SHA2_384:
		case EHashFunction::SHA2_512: return SHA_Data(hashState->SubState, data, dataSize); break;
		default: return false;
		}
	}

	bool Hash_Final(void* state, void* digest, size_t* digestSize, bool reset)
	{
		if (!state)
			return false;
		auto hashState = (HashState*) state;
		switch (hashState->HashFunction)
		{
		case EHashFunction::SHA1:
		case EHashFunction::SHA2_224:
		case EHashFunction::SHA2_256:
		case EHashFunction::SHA2_384:
		case EHashFunction::SHA2_512: return SHA_Final(hashState->SubState, digest, digestSize, reset); break;
		default: return false;
		}
	}

	static bool HMAC_Main(void* hashState, const void* key, size_t keySize, const void* code, size_t codeSize, void* digest, size_t* digestSize)
	{
		if (!hashState || !key || !code || !digest || !digestSize)
			return false;

		uint8_t block[128];
		uint8_t block2[128];
		uint8_t tempDigest[64];
		size_t  blockSize = 0;
		Hash_BlockSize(hashState, &blockSize);
		Hash_DigestSize(hashState, digestSize);

		if (keySize > blockSize)
		{
			if (!Hash_Data(hashState, key, keySize) ||
				!Hash_Final(hashState, block, digestSize, true))
				return false;
			keySize = *digestSize;
		}
		else if (keySize <= blockSize)
		{
			memcpy(block, key, keySize);
		}
		memset(block + keySize, 0, blockSize - keySize);

		for (size_t i = 0; i < blockSize; ++i)
			block2[i] = block[i] ^ 0x36;
		if (!Hash_Data(hashState, block2, blockSize) ||
			!Hash_Data(hashState, code, codeSize) ||
			!Hash_Final(hashState, tempDigest, digestSize, true))
			return false;

		for (size_t i = 0; i < blockSize; ++i)
			block[i] = block[i] ^ 0x5C;
		if (!Hash_Data(hashState, block2, blockSize) ||
			!Hash_Data(hashState, tempDigest, *digestSize) ||
			!Hash_Final(hashState, digest, digestSize, true))
			return false;
		return true;
	}

	bool HMAC(EHashFunction hashFunction, const void* key, size_t keySize, const void* code, size_t codeSize, void* digest, size_t* digestSize)
	{
		if (!key || !code || !digest || !digestSize)
			return false;

		void* hashState = nullptr;
		if (!Hash_Init(&hashState, hashFunction))
			return false;
		bool result = HMAC_Main(hashState, key, keySize, code, codeSize, digest, digestSize);
		Hash_Destroy(hashState);
		return result;
	}

	bool CalcHOTP(EHashFunction hashFunction, const void* key, size_t keySize, uint64_t counter, char* buffer, uint8_t digits)
	{
		static constexpr size_t c_Pow10[] = { 1ULL, 10ULL, 100ULL, 1000ULL, 10000ULL, 100000ULL, 1000000ULL, 10000000ULL, 100000000ULL, 1000000000ULL, 10000000000ULL, 100000000000ULL, 1000000000000ULL, 10000000000000ULL, 100000000000000ULL, 1000000000000000ULL, 10000000000000000ULL, 100000000000000000ULL, 1000000000000000000ULL, 10000000000000000000ULL, ~0ULL, ~0ULL, ~0ULL, ~0ULL, ~0ULL, ~0ULL, ~0ULL, ~0ULL, ~0ULL, ~0ULL, ~0ULL, ~0ULL };

		uint8_t code[8];
		code[0] = (counter >> 56) & 0xFF;
		code[1] = (counter >> 48) & 0xFF;
		code[2] = (counter >> 40) & 0xFF;
		code[3] = (counter >> 32) & 0xFF;
		code[4] = (counter >> 24) & 0xFF;
		code[5] = (counter >> 16) & 0xFF;
		code[6] = (counter >> 8) & 0xFF;
		code[7] = counter & 0xFF;

		uint8_t digest[64];
		size_t  digestSize = 64;
		if (!HMAC(hashFunction, key, keySize, code, 8, digest, &digestSize))
			return false;

		uint8_t  offset = digest[digestSize - 1] & 0xF;
		uint32_t binary = ((digest[offset] & 0x7F) << 24) |
						  ((digest[offset + 1] & 0xFF) << 16) |
						  ((digest[offset + 2] & 0xFF) << 8) |
						  (digest[offset + 3] & 0xFF);

		uint32_t otp   = binary % c_Pow10[digits & 0b11111];
		buffer[digits] = '\0';
		for (size_t i = 0, j = digits - 1; i < digits; ++i, --j)
		{
			buffer[j] = '0' + (otp % 10);
			otp      /= 10;
		}
		return true;
	}

	bool CalcTOTP(EHashFunction hashFunction, const void* key, size_t keySize, uint64_t t0, uint64_t tx, char* buffer, uint8_t digits)
	{
		return CalcHOTP(hashFunction, key, keySize, (Time::CurUnixTime() - t0) / tx, buffer, digits);
	}
} // namespace Crypto