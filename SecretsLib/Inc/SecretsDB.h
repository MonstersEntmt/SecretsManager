#pragma once

#include "Concurrency/Mutex.h"
#include "Utils/DataView.h"
#include "Utils/UUID.h"

#include <cstdint>

#include <filesystem>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace Database
{
	namespace Raw
	{
		using SecretEntryFlags = uint64_t;

		namespace SecretEntryFlag
		{
			static constexpr SecretEntryFlags None        = 0x0000'0000'0000'0000ULL;
			static constexpr SecretEntryFlags SeparateKey = 0x0000'0000'0000'0001ULL;
		} // namespace SecretEntryFlag

		struct DataRef
		{
			uint64_t Offset;
			uint64_t Length;
		};

		struct SecretEntry
		{
			UUID             ID;
			SecretEntryFlags Flags;
			DataRef          Name; // In RootHeader::Data
			DataRef          Data; // In SecretData
			uint64_t         Reserved;
		};

		enum class ESyncMethod : uint8_t
		{
			// OneDrive,
			Unknown = 0xFF
		};

		struct SyncData
		{
			UUID        ID;
			DataRef     Path; // In RootHeader::Data
			uint64_t    Data[3];
			ESyncMethod Method;
			uint8_t     Reserved[7];
		};

		enum class EAuditOp : uint8_t
		{
			CreateSecret = 0,
			RenameSecret,
			DeleteSecret,
			CreateSync,
			ModifySync,
			DeleteSync
		};

		struct Audit
		{
			EAuditOp Op;
			uint8_t  Reserved[7];
			uint64_t Time;
			UUID     SecretID;
		};

		// All UUIDs with variant 11 are reserved, with the following UUIDs defined
		// 'OTP'      => 32AAE9A1-B6C8-4D48-FC36-ED087620C6AA, Name should be (0,0), Value is an OTPHeader
		// 'EMail'    => 8F32206F-2C25-4A5F-CC6D-EF440EE7CC7B, Name should be (0,0), Value is plaintext
		// 'Username' => 048B2907-3BAC-4F04-D76C-EDDE34EF2725, Name should be (0,0), Value is plaintext
		// 'Password' => 2F914E10-D7D7-4296-FCC3-4C235647E720, Name should be (0,0), Value is plaintext, hide in UI
		// 'Website'  => 9B3F190A-6428-4677-C763-6C53ADF687B1, Name should be (0,0), Value is plaintext
		struct Entry
		{
			UUID     ID;
			DataRef  Name;  // In SecretHeader::Data
			DataRef  Value; // In SecretHeader::Data
			uint64_t Reserved[2];
		};

		enum class ESecretAuditOp : uint8_t
		{
			CreateEntry = 0,
			RenameEntry,
			ModifyEntry,
			RemoveEntry
		};

		struct SecretAudit
		{
			ESecretAuditOp Op;
			uint8_t        Reserved[7];
			uint64_t       Time;
			UUID           EntryID;
		};

		struct Header
		{
			uint16_t Version;
			uint16_t Reserved[3];
			uint64_t RootSize;
			// Assume everything beyond here is encrypted
			// RootHeader   Root;
			// SecretHeader SecretData[N];
		};

		struct RootHeader
		{
			uint8_t  Checksum[64];
			uint64_t SecretCount;
			uint64_t SyncCount;
			uint64_t AuditCount;
			uint64_t Reserved[5];
			// SecretEntry Secrets[SecretCount];
			// SyncData    Syncs[SyncCount];
			// Audit       Audits[AuditCount];
			// uint8_t     Data[...];
		};

		struct SecretHeader
		{
			uint8_t  Checksum[64];
			uint64_t EntryCount;
			uint64_t AuditCount;
			uint64_t Reserved[6];
			// Entry       Entries[EntryCount];
			// SecretAudit Audits[AuditCount];
			// uint8_t     Data[...];
		};

		enum class EOTPMethod : uint8_t
		{
			None = 0,
			HOTP,
			TOTP
		};

		enum class EOTPHashMethod : uint8_t
		{
			SHA1 = 0,
			SHA2_224,
			SHA2_256,
			SHA2_384,
			SHA2_512,
			SHA3_224,
			SHA3_256,
			SHA3_384,
			SHA3_512
		};

		struct OTPHeader
		{
			EOTPMethod     Method;
			EOTPHashMethod Hash;
			uint8_t        Digits;
			uint8_t        Reserved[5];
			uint64_t       Counter;
			uint64_t       T0;
			// uint8_t Key[...];
		};
	} // namespace Raw

	struct RCGCData
	{
	private:
		struct DataRefHasher
		{
			using is_transparent = void;

			DataRefHasher(RCGCData* data)
				: Data(data) {}

			size_t Hash(ByteView data) const { return std::hash<std::string_view> {}(std::string_view { (const char*) data.begin(), (const char*) data.end() }); }

			size_t operator()(const Raw::DataRef& dataRef) const { return Hash(Data->GetDataView(dataRef)); }
			size_t operator()(const char* str) const { return std::hash<std::string_view> {}(str); }
			size_t operator()(std::string_view str) const { return std::hash<std::string_view> {}(str); }
			size_t operator()(const std::string& str) const { return std::hash<std::string_view> {}(str); }
			template <class U>
			size_t operator()(DataView<U> data) const
			{
				return Hash(ByteView { (const uint8_t*) data.begin(), (const uint8_t*) data.end() });
			}

			RCGCData* Data;
		};

		struct DataRefKeyEqual
		{
			using is_transparent = void;

			DataRefKeyEqual(RCGCData* data)
				: Data(data) {}

			bool Compare(ByteView lhs, ByteView rhs) const { return lhs.size() == rhs.size() && memcmp(lhs.begin(), rhs.begin(), lhs.size()) == 0; }

			template <class U>
			ByteView ToByteView(DataView<U> data) const
			{
				return ByteView { (const uint8_t*) data.begin(), (const uint8_t*) data.end() };
			}
			ByteView ToByteView(const Raw::DataRef& ref) const { return ToByteView(Data->GetDataView(ref)); }
			ByteView ToByteView(std::string_view str) const { return ByteView { (const uint8_t*) str.data(), str.size() }; }
			ByteView ToByteView(const std::string& str) const { return ToByteView(std::string_view { str }); }
			ByteView ToByteView(const char* str) const { return ToByteView(std::string_view { str }); }

			bool operator()(const Raw::DataRef& lhs, const Raw::DataRef& rhs) const { return lhs.Offset == rhs.Offset && lhs.Length == rhs.Length; }
			bool operator()(const Raw::DataRef& lhs, const char* rhs) const { return Compare(ToByteView(lhs), ToByteView(rhs)); }
			bool operator()(const Raw::DataRef& lhs, std::string_view rhs) const { return Compare(ToByteView(lhs), ToByteView(rhs)); }
			bool operator()(const Raw::DataRef& lhs, const std::string& rhs) const { return Compare(ToByteView(lhs), ToByteView(rhs)); }
			bool operator()(const char* lhs, const Raw::DataRef& rhs) const { return Compare(ToByteView(lhs), ToByteView(rhs)); }
			bool operator()(const char* lhs, const char* rhs) const { return Compare(ToByteView(lhs), ToByteView(rhs)); }
			bool operator()(const char* lhs, std::string_view rhs) const { return Compare(ToByteView(lhs), ToByteView(rhs)); }
			bool operator()(const char* lhs, const std::string& rhs) const { return Compare(ToByteView(lhs), ToByteView(rhs)); }
			bool operator()(std::string_view lhs, const Raw::DataRef& rhs) const { return Compare(ToByteView(lhs), ToByteView(rhs)); }
			bool operator()(std::string_view lhs, const char* rhs) const { return Compare(ToByteView(lhs), ToByteView(rhs)); }
			bool operator()(std::string_view lhs, std::string_view rhs) const { return Compare(ToByteView(lhs), ToByteView(rhs)); }
			bool operator()(std::string_view lhs, const std::string& rhs) const { return Compare(ToByteView(lhs), ToByteView(rhs)); }
			bool operator()(const std::string& lhs, const Raw::DataRef& rhs) const { return Compare(ToByteView(lhs), ToByteView(rhs)); }
			bool operator()(const std::string& lhs, const char* rhs) const { return Compare(ToByteView(lhs), ToByteView(rhs)); }
			bool operator()(const std::string& lhs, std::string_view rhs) const { return Compare(ToByteView(lhs), ToByteView(rhs)); }
			bool operator()(const std::string& lhs, const std::string& rhs) const { return Compare(ToByteView(lhs), ToByteView(rhs)); }

			template <class U>
			bool operator()(const Raw::DataRef& lhs, DataView<U> rhs) const
			{
				return Compare(ToByteView(lhs), ToByteView(rhs));
			}
			template <class U>
			bool operator()(const char* lhs, DataView<U> rhs) const
			{
				return Compare(ToByteView(lhs), ToByteView(rhs));
			}
			template <class U>
			bool operator()(std::string_view lhs, DataView<U> rhs) const
			{
				return Compare(ToByteView(lhs), ToByteView(rhs));
			}
			template <class U>
			bool operator()(const std::string& lhs, DataView<U> rhs) const
			{
				return Compare(ToByteView(lhs), ToByteView(rhs));
			}
			template <class U>
			bool operator()(DataView<U> lhs, const Raw::DataRef& rhs) const
			{
				return Compare(ToByteView(lhs), ToByteView(rhs));
			}
			template <class U>
			bool operator()(DataView<U> lhs, const char* rhs) const
			{
				return Compare(ToByteView(lhs), ToByteView(rhs));
			}
			template <class U>
			bool operator()(DataView<U> lhs, std::string_view rhs) const
			{
				return Compare(ToByteView(lhs), ToByteView(rhs));
			}
			template <class U>
			bool operator()(DataView<U> lhs, const std::string& rhs) const
			{
				return Compare(ToByteView(lhs), ToByteView(rhs));
			}
			template <class U1, class U2>
			bool operator()(DataView<U1> lhs, DataView<U2> rhs) const
			{
				return Compare(ToByteView(lhs), ToByteView(rhs));
			}

			RCGCData* Data;
		};

	public:
		RCGCData();
		RCGCData(RCGCData&& move) noexcept;
		~RCGCData();

		RCGCData& operator=(RCGCData&& move) noexcept;

		void     BeginWriteData() { Concurrency::Lock(m_DataMutex); }
		void     EndWriteData() { Concurrency::Unlock(m_DataMutex); }
		void     BeginReadData() { Concurrency::LockShared(m_DataMutex); }
		void     EndReadData() { Concurrency::UnlockShared(m_DataMutex); }
		ByteView GetDataView(const Raw::DataRef& ref) const { return ByteView { data() + ref.Offset, ref.Length }; }

		void clear();
		void resize(size_t size);

		uint8_t*       data() { return m_Data.data(); }
		const uint8_t* data() const { return m_Data.data(); }
		size_t         size() const { return m_Data.size(); }

		Raw::DataRef GetDataRef(ByteView data);
		Raw::DataRef IncDataRef(ByteView data);

		Raw::DataRef GetDataRef(std::string_view str) { return GetDataRef(ByteView { (const uint8_t*) str.data(), str.size() }); }
		Raw::DataRef IncDataRef(std::string_view str) { return IncDataRef(ByteView { (const uint8_t*) str.data(), str.size() }); }

		void IncDataRef(Raw::DataRef ref);
		void DecDataRef(Raw::DataRef ref);
		void GCClean(void (*moveNotifier)(void* userdata, uint64_t minOffset, uint64_t maxOffset, int64_t amount), void* userdata);

	private:
		using RefCountT = std::unordered_map<Raw::DataRef, std::atomic_uint64_t, DataRefHasher, DataRefKeyEqual>;
		using RSM       = Concurrency::RecursiveSharedMutex;

		std::vector<uint8_t>      m_Data;
		RefCountT                 m_RefCounts;
		std::vector<Raw::DataRef> m_GCRefs;

		RSM                m_DataMutex;
		Concurrency::Mutex m_GCMutex;
	};

	struct Key
	{
		uint8_t Bytes[48];
	};

	struct Secret
	{
		Key                           SecretKey;
		UUID                          ID;
		std::vector<Raw::Entry>       Entries;
		std::vector<Raw::SecretAudit> Audits;
		RCGCData                      Data;

		std::unordered_map<UUID, uint64_t> EntryIndex;

		void Reset();

		bool IsDecrypted() const { return ID != UUID {}; }

		void BeginWriteData() { Data.BeginWriteData(); }
		void EndWriteData() { Data.EndWriteData(); }
		void BeginReadData() { Data.BeginReadData(); }
		void EndReadData() { Data.EndReadData(); }

		// Ensure this call is wrapped inside BeginReadData() and EndReadData() and copied somewhere else if needed for an extended period of time
		ByteView GetByteView(const Raw::DataRef& ref);
		// Ensure this call is wrapped inside BeginReadData() and EndReadData() and copied somewhere else if needed for an extended period of time
		std::string_view GetStringView(const Raw::DataRef& ref);

		bool SetEntryName(UUID uuid, std::string_view name);
		bool SetEntryValue(UUID uuid, std::string_view value);
		bool GetEntryInfo(UUID uuid, Raw::Entry& entryInfo);

		bool FindEntries(DataView<const std::string_view> keywords, bool (*callback)(void* userdata, const Raw::Entry& entryInfo), void* userdata);

		bool EnsureEntry(UUID uuid);
		UUID NewEntry();
		void RemoveEntry(UUID uuid);

		void GCClean();
	};

	struct Root
	{
		Key                   RootKey; // This should probably be shuffled in some form, to stop memory introspectors
		std::fstream          File;
		std::filesystem::path Filepath;
		uint64_t              SecretDataOffset;
		uint64_t              SecretDataSize;

		std::vector<Raw::SecretEntry> Secrets;
		std::vector<Raw::SyncData>    Syncs;
		std::vector<Raw::Audit>       Audits;
		RCGCData                      Data;

		std::unordered_map<UUID, uint64_t> SecretIndex;
		std::unordered_map<UUID, uint64_t> SyncIndex;

		void Reset();

		bool IsDecrypted() const { return File.is_open(); }

		bool DecryptSecret(Secret& secret, UUID uuid, const Key& key);
		bool EncryptSecret(Secret& secret);

		void BeginWriteData() { Data.BeginWriteData(); }
		void EndWriteData() { Data.EndWriteData(); }
		void BeginReadData() { Data.BeginReadData(); }
		void EndReadData() { Data.EndReadData(); }

		// Ensure this call is wrapped inside BeginReadData() and EndReadData() and copied somewhere else if needed for an extended period of time
		ByteView GetByteView(const Raw::DataRef& ref);
		// Ensure this call is wrapped inside BeginReadData() and EndReadData() and copied somewhere else if needed for an extended period of time
		std::string_view GetStringView(const Raw::DataRef& ref);

		bool SetSecretName(UUID uuid, std::string_view name);
		bool GetSecretInfo(UUID uuid, Raw::SecretEntry& secretInfo);
		bool GetSyncInfo(UUID uuid, Raw::SyncData& syncInfo);

		bool FindSecrets(DataView<const std::string_view> keywords, bool (*callback)(void* userdata, const Raw::SecretEntry& secretInfo), void* userdata);
		bool FindSyncs(bool (*callback)(void* userdata, const Raw::SyncData& syncInfo), void* userdata);

		// TODO(MarcasRealAccount): Add sync functions

		UUID NewSecret(const Key& key);
		UUID NewSecret() { return NewSecret(RootKey); }
		void RemoveSecret(UUID uuid);
		void RemoveSync(UUID uuid);

		void GCClean();

		// Internal functions
		void         RemoveSecretData(const Raw::DataRef& ref);
		Raw::DataRef AddSecretData(ByteView bytes);
	};

	bool DecryptRoot(const std::filesystem::path& filepath, Root& root, const Key& key);
	bool EncryptRoot(Root& root);
} // namespace Database