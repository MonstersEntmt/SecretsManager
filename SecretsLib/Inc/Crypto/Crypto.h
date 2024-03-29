#pragma once

#include <cstddef>
#include <cstdint>

#include <type_traits>

namespace Crypto
{
	using ssize_t = std::make_signed_t<size_t>;

	enum class ESHAFunction : uint32_t
	{
		SHA1     = 0U << 8,
		SHA2     = 1U << 8,
		SHA3     = 2U << 8,
		SHA2_224 = 1,
		SHA2_256 = 2,
		SHA2_384 = 3,
		SHA2_512 = 4,
		SHA3_224 = 5,
		SHA3_256 = 6,
		SHA3_384 = 7,
		SHA3_512 = 8
	};

	enum class EHashFunction
	{
		SHA1,
		SHA2_224,
		SHA2_256,
		SHA2_384,
		SHA2_512
	};

	bool SHA_Init(void** state, ESHAFunction shaFunction);
	bool SHA_Reset(void* state);
	bool SHA_Destroy(void* state);
	bool SHA_DigestSize(void* state, size_t* digestSize);
	bool SHA_BlockSize(void* state, size_t* blockSize);
	bool SHA_Data(void* state, const void* data, size_t dataSize);
	bool SHA_Final(void* state, void* digest, size_t* digestSize, bool reset = false);

	bool Hash_Init(void** state, EHashFunction hashFunction);
	bool Hash_Reset(void* state);
	bool Hash_Destroy(void* state);
	bool Hash_DigestSize(void* state, size_t* digestSize);
	bool Hash_BlockSize(void* state, size_t* blockSize);
	bool Hash_Data(void* state, const void* data, size_t dataSize);
	bool Hash_Final(void* state, void* digest, size_t* digestSize, bool reset = false);

	bool AES_EncryptSize(size_t dataSize, size_t* encryptedDataSize);
	bool AES_DecryptSize(size_t dataSize, size_t* decryptedDataSize);
	bool AES_ECB_Init(void** state, const void* key, size_t keySize);
	bool AES_CBC_Init(void** state, const void* key, size_t keySize, const void* iv, size_t ivSize);
	bool AES_ECB_Reset(void* state, const void* key, size_t keySize);
	bool AES_CBC_Reset(void* state, const void* key, size_t keySize, const void* iv, size_t ivSize);
	bool AES_Destroy(void* state);
	bool AES_EncryptData(void* state, const void* data, size_t dataSize, void* encryptedData, ssize_t* encryptedDataSize);
	bool AES_DecryptData(void* state, const void* data, size_t dataSize, void* decryptedData, ssize_t* decryptedDataSize);
	bool AES_EncryptFinal(void* state, const void* data, size_t dataSize, void* encryptedData, ssize_t* encryptedDataSize);
	bool AES_DecryptFinal(void* state, const void* data, size_t dataSize, void* decryptedData, ssize_t* decryptedDataSize);

	bool HMAC(EHashFunction hashFunction, const void* key, size_t keySize, const void* code, size_t codeSize, void* digest, size_t* digestSize);
	bool CalcHOTP(EHashFunction hashFunction, const void* key, size_t keySize, uint64_t counter, char* buffer, uint8_t digits);
	bool CalcTOTP(EHashFunction hashFunction, const void* key, size_t keySize, uint64_t t0, uint64_t tx, char* buffer, uint8_t digits);

	inline bool SHA(ESHAFunction shaFunction, const void* data, size_t dataSize, void* digest, size_t* digestSize)
	{
		void* state = nullptr;
		if (!SHA_Init(&state, shaFunction))
			return false;
		bool result = SHA_Data(state, data, dataSize) &&
					  SHA_Final(state, digest, digestSize);
		SHA_Destroy(state);
		return result;
	}

	inline bool Hash(EHashFunction hashFunction, const void* data, size_t dataSize, void* digest, size_t* digestSize)
	{
		void* state = nullptr;
		if (!Hash_Init(&state, hashFunction))
			return false;
		bool result = Hash_Data(state, data, dataSize) &&
					  Hash_Final(state, digest, digestSize);
		Hash_Destroy(state);
		return result;
	}

	inline bool AES_ECB_Encrypt(const void* key, size_t keySize, const void* data, size_t dataSize, void* encryptedData, size_t* encryptedDataSize)
	{
		void* state = nullptr;
		if (!AES_ECB_Init(&state, key, keySize))
			return false;
		ssize_t size       = 0;
		bool    result     = AES_EncryptFinal(state, data, dataSize, encryptedData, &size);
		*encryptedDataSize = size;
		AES_Destroy(state);
		return result;
	}

	inline bool AES_ECB_Decrypt(const void* key, size_t keySize, const void* data, size_t dataSize, void* decryptedData, size_t* decryptedDataSize)
	{
		void* state = nullptr;
		if (!AES_ECB_Init(&state, key, keySize))
			return false;
		ssize_t size       = 0;
		bool    result     = AES_DecryptFinal(state, data, dataSize, decryptedData, &size);
		*decryptedDataSize = size;
		AES_Destroy(state);
		return result;
	}

	inline bool AES_CBC_Encrypt(const void* key, size_t keySize, const void* iv, size_t ivSize, const void* data, size_t dataSize, void* encryptedData, size_t* encryptedDataSize)
	{
		void* state = nullptr;
		if (!AES_CBC_Init(&state, key, keySize, iv, ivSize))
			return false;
		ssize_t size       = 0;
		bool    result     = AES_EncryptFinal(state, data, dataSize, encryptedData, &size);
		*encryptedDataSize = size;
		AES_Destroy(state);
		return result;
	}

	inline bool AES_CBC_Decrypt(const void* key, size_t keySize, const void* iv, size_t ivSize, const void* data, size_t dataSize, void* decryptedData, size_t* decryptedDataSize)
	{
		void* state = nullptr;
		if (!AES_CBC_Init(&state, key, keySize, iv, ivSize))
			return false;
		ssize_t size       = 0;
		bool    result     = AES_DecryptFinal(state, data, dataSize, decryptedData, &size);
		*decryptedDataSize = size;
		AES_Destroy(state);
		return result;
	}
} // namespace Crypto