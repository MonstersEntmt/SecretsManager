#include "SecretsDB.h"

#include "Crypto/Crypto.h"
#include "Utils/Time.h"

#include <algorithm>

namespace Database
{
	RCGCData::RCGCData()
		: m_RefCounts(0, DataRefHasher { this }, DataRefKeyEqual { this })
	{
	}

	RCGCData::RCGCData(RCGCData&& move) noexcept
		: m_Data(std::move(move.m_Data)),
		  m_RefCounts(std::move(move.m_RefCounts)),
		  m_GCRefs(std::move(move.m_GCRefs))
	{
	}

	RCGCData::~RCGCData() {}

	RCGCData& RCGCData::operator=(RCGCData&& move) noexcept
	{
		m_Data      = std::move(move.m_Data);
		m_RefCounts = std::move(move.m_RefCounts);
		m_GCRefs    = std::move(move.m_GCRefs);
		return *this;
	}

	void RCGCData::clear()
	{
		auto lock = Concurrency::ScopedLock(m_DataMutex);
		m_Data.clear();
		m_RefCounts.clear();
		m_GCRefs.clear();
	}

	void RCGCData::resize(size_t size)
	{
		auto lock = Concurrency::ScopedLock(m_DataMutex);
		m_Data.resize(size);
	}

	Raw::DataRef RCGCData::GetDataRef(ByteView data)
	{
		auto lock = Concurrency::ScopedSharedLock(m_DataMutex);
		auto itr  = m_RefCounts.find(data);
		if (itr == m_RefCounts.end())
			return { ~0ULL, ~0ULL };
		return itr->first;
	}

	Raw::DataRef RCGCData::IncDataRef(ByteView data)
	{
		Concurrency::LockShared(m_DataMutex);
		auto itr = m_RefCounts.find(data);
		if (itr != m_RefCounts.end())
		{
			Concurrency::UnlockShared(m_DataMutex);
			return itr->first;
		}
		Concurrency::UnlockShared(m_DataMutex);
		Concurrency::Lock(m_DataMutex);
		Raw::DataRef ref = { m_Data.size(), data.size() };
		m_Data.insert(m_Data.end(), data.begin(), data.end());
		IncDataRef(ref);
		Concurrency::Unlock(m_DataMutex);
		return ref;
	}

	void RCGCData::IncDataRef(Raw::DataRef ref)
	{
		if (ref.Offset == ~0ULL)
			return;

		auto lock = Concurrency::ScopedSharedLock(m_DataMutex);
		++m_RefCounts[ref];
	}

	void RCGCData::DecDataRef(Raw::DataRef ref)
	{
		if (ref.Offset == ~0ULL)
			return;

		auto lock = Concurrency::ScopedSharedLock(m_DataMutex);
		// When the ref count hits 0 we don't immediately remove the data, instead we wait for a GC cleaning to happen, this is so we can potentially have multiple threads accessing the data incrementing and decrementing already existing regions in data without needing full shifting to take place.
		auto itr = m_RefCounts.find(ref);
		if (itr == m_RefCounts.end())
			return;
		if (itr->second == 0)
			return;
		if (--itr->second == 0)
		{
			auto lock2 = Concurrency::ScopedLock(m_GCMutex);
			m_GCRefs.push_back(ref);
		}
	}

	void RCGCData::GCClean(void (*moveNotifier)(void* userdata, uint64_t minOffset, uint64_t maxOffset, int64_t amount), void* userdata)
	{
		auto lock = Concurrency::ScopedLock(m_DataMutex);

		std::vector<Raw::DataRef> queue;
		{
			auto lock2 = Concurrency::ScopedLock(m_GCMutex);
			queue.swap(m_GCRefs);
		}

		std::sort(queue.begin(), queue.end(), [](const Raw::DataRef& lhs, const Raw::DataRef& rhs) -> bool { return lhs.Offset < rhs.Offset; });
		uint64_t shift = 0;
		for (size_t i = 0; i < queue.size(); ++i)
		{
			if (m_RefCounts[queue[i]] != 0)
				continue;

			if (i < queue.size() - 1)
			{
				memmove(m_Data.data() + queue[i].Offset - shift, m_Data.data() + queue[i + 1].Offset, queue[i].Length);
				moveNotifier(userdata, queue[i].Offset, queue[i + 1].Offset, -(int64_t) queue[i].Length);
			}
			else
			{
				moveNotifier(userdata, queue[i].Offset, ~0ULL, -(int64_t) queue[i].Length);
			}
			shift += queue[i].Length;
		}
		m_Data.resize(m_Data.size() - shift);
	}

	void Secret::Reset()
	{
		memset(&SecretKey, 0, sizeof(SecretKey));
		ID = {};
		Entries.clear();
		Audits.clear();
		Data.clear();
		EntryIndex.clear();
	}

	ByteView Secret::GetByteView(const Raw::DataRef& ref)
	{
		BeginReadData();
		ByteView view = Data.GetDataView(ref);
		EndReadData();
		return view;
	}

	std::string_view Secret::GetStringView(const Raw::DataRef& ref)
	{
		BeginReadData();
		ByteView view = Data.GetDataView(ref);
		EndReadData();
		return std::string_view { (const char*) view.begin(), (const char*) view.end() };
	}

	bool Secret::SetEntryName(UUID uuid, std::string_view name)
	{
		BeginReadData();
		auto itr = EntryIndex.find(uuid);
		if (itr == EntryIndex.end())
		{
			EndReadData();
			return false;
		}
		EndReadData();
		BeginWriteData();
		auto& entry = Entries[itr->second];
		Data.DecDataRef(entry.Name);
		entry.Name        = Data.IncDataRef(name);
		auto& audit       = Audits.emplace_back();
		audit.Op          = Raw::ESecretAuditOp::ModifyEntry;
		audit.Reserved[0] = 0;
		audit.Reserved[1] = 0;
		audit.Reserved[2] = 0;
		audit.Reserved[3] = 0;
		audit.Reserved[4] = 0;
		audit.Reserved[5] = 0;
		audit.Reserved[6] = 0;
		audit.Time        = Time::CurUnixTime();
		audit.EntryID     = entry.ID;
		EndWriteData();
		return true;
	}

	bool Secret::SetEntryValue(UUID uuid, std::string_view value)
	{
		BeginReadData();
		auto itr = EntryIndex.find(uuid);
		if (itr == EntryIndex.end())
		{
			EndReadData();
			return false;
		}
		EndReadData();
		BeginWriteData();
		auto& entry = Entries[itr->second];
		Data.DecDataRef(entry.Value);
		entry.Value       = Data.IncDataRef(value);
		auto& audit       = Audits.emplace_back();
		audit.Op          = Raw::ESecretAuditOp::ModifyEntry;
		audit.Reserved[0] = 0;
		audit.Reserved[1] = 0;
		audit.Reserved[2] = 0;
		audit.Reserved[3] = 0;
		audit.Reserved[4] = 0;
		audit.Reserved[5] = 0;
		audit.Reserved[6] = 0;
		audit.Time        = Time::CurUnixTime();
		audit.EntryID     = entry.ID;
		EndWriteData();
		return true;
	}

	bool Secret::GetEntryInfo(UUID uuid, Raw::Entry& entryInfo)
	{
		BeginReadData();
		auto itr = EntryIndex.find(uuid);
		if (itr == EntryIndex.end())
		{
			EndReadData();
			entryInfo = {};
			return false;
		}

		entryInfo = Entries[itr->second];
		EndReadData();
		return true;
	}

	bool Secret::FindEntries(DataView<const std::string_view> keywords, bool (*callback)(void* userdata, const Raw::Entry& entryInfo), void* userdata)
	{
		BeginReadData();
		if (keywords.empty())
		{
			for (size_t i = 0; i < Entries.size(); ++i)
			{
				if (!callback(userdata, Entries[i]))
					break;
			}
		}
		else
		{
			EndReadData();
			return false;
		}
		EndReadData();
		return true;
	}

	bool Secret::EnsureEntry(UUID uuid)
	{
		BeginReadData();
		auto itr = EntryIndex.find(uuid);
		if (itr != EntryIndex.end())
		{
			EndReadData();
			return true;
		}
		EndReadData();
		BeginWriteData();
		uint64_t index       = Entries.size();
		auto&    entry       = Entries.emplace_back();
		entry.ID             = uuid;
		EntryIndex[entry.ID] = index;
		entry.Name           = Data.IncDataRef(std::format("Secret {}", entry.ID));
		entry.Value          = { ~0ULL, ~0ULL };
		entry.Reserved[0]    = 0;
		entry.Reserved[1]    = 0;
		auto& audit          = Audits.emplace_back();
		audit.Op             = Raw::ESecretAuditOp::CreateEntry;
		audit.Reserved[0]    = 0;
		audit.Reserved[1]    = 0;
		audit.Reserved[2]    = 0;
		audit.Reserved[3]    = 0;
		audit.Reserved[4]    = 0;
		audit.Reserved[5]    = 0;
		audit.Reserved[6]    = 0;
		audit.Time           = Time::CurUnixTime();
		audit.EntryID        = uuid;
		EndWriteData();
		return true;
	}

	UUID Secret::NewEntry()
	{
		BeginWriteData();
		uint64_t index       = Entries.size();
		auto&    entry       = Entries.emplace_back();
		entry.ID             = GenUniqueUUID([this](const UUID& uuid) -> bool { return EntryIndex.contains(uuid); });
		EntryIndex[entry.ID] = index;
		entry.Name           = Data.IncDataRef(std::format("Secret {}", entry.ID));
		entry.Value          = { ~0ULL, ~0ULL };
		entry.Reserved[0]    = 0;
		entry.Reserved[1]    = 0;
		UUID  id             = entry.ID;
		auto& audit          = Audits.emplace_back();
		audit.Op             = Raw::ESecretAuditOp::CreateEntry;
		audit.Reserved[0]    = 0;
		audit.Reserved[1]    = 0;
		audit.Reserved[2]    = 0;
		audit.Reserved[3]    = 0;
		audit.Reserved[4]    = 0;
		audit.Reserved[5]    = 0;
		audit.Reserved[6]    = 0;
		audit.Time           = Time::CurUnixTime();
		audit.EntryID        = id;
		EndWriteData();
		return id;
	}

	void Secret::RemoveEntry(UUID uuid)
	{
		BeginReadData();
		auto itr = EntryIndex.find(uuid);
		if (itr == EntryIndex.end())
		{
			EndReadData();
			return;
		}

		if (itr->second >= Entries.size())
		{
			EndReadData();
			BeginWriteData();
			EntryIndex.erase(itr);
			EndWriteData();
			return;
		}
		EndReadData();

		BeginWriteData();
		auto& secret = Entries[itr->second];
		Data.DecDataRef(secret.Name);
		Data.DecDataRef(secret.Value);
		Entries.erase(Entries.begin() + itr->second);
		for (auto& entryIndex : EntryIndex)
		{
			if (entryIndex.second > itr->second)
				--entryIndex.second;
		}
		EntryIndex.erase(itr);
		auto& audit       = Audits.emplace_back();
		audit.Op          = Raw::ESecretAuditOp::RemoveEntry;
		audit.Reserved[0] = 0;
		audit.Reserved[1] = 0;
		audit.Reserved[2] = 0;
		audit.Reserved[3] = 0;
		audit.Reserved[4] = 0;
		audit.Reserved[5] = 0;
		audit.Reserved[6] = 0;
		audit.Time        = Time::CurUnixTime();
		audit.EntryID     = uuid;
		EndWriteData();
	}

	void Secret::GCClean()
	{
		struct Userdata
		{
			Secret* secret;
		} userdata;
		userdata.secret = this;

		Data.GCClean(
			[](void* userdata, uint64_t minOffset, uint64_t maxOffset, int64_t amount) {
				Secret* secret = ((Userdata*) userdata)->secret;

				for (auto& entry : secret->Entries)
				{
					if (entry.Name.Offset > minOffset && entry.Name.Offset < maxOffset)
						entry.Name.Offset += amount;
					if (entry.Value.Offset > minOffset && entry.Value.Offset < maxOffset)
						entry.Value.Offset += amount;
				}
			},
			&userdata);
	}

	void Root::Reset()
	{
		memset(&RootKey, 0, sizeof(RootKey));
		File.close();
		Filepath.clear();
		SecretDataOffset = 0;
		SecretDataSize   = 0;
		Secrets.clear();
		Syncs.clear();
		Audits.clear();
		Data.clear();
		SecretIndex.clear();
		SyncIndex.clear();
	}

	bool Root::DecryptSecret(Secret& secret, UUID uuid, const Key& key)
	{
		BeginReadData();
		auto itr = SecretIndex.find(uuid);
		if (itr == SecretIndex.end())
		{
			EndReadData();
			return false;
		}

		secret.ID = uuid;
		secret.Entries.clear();
		secret.Audits.clear();
		secret.Data.clear();
		secret.EntryIndex.clear();

		auto& secretEntry = Secrets[itr->second];

		std::vector<uint8_t> encryptedData;
		encryptedData.resize(secretEntry.Data.Length);
		File.seekg(SecretDataOffset + secretEntry.Data.Offset);
		File.read((char*) encryptedData.data(), secretEntry.Data.Length);

		size_t decryptedSize = 0;
		Crypto::AES_DecryptSize(secretEntry.Data.Length, &decryptedSize);
		std::vector<uint8_t> decryptedData;
		decryptedData.resize(decryptedSize);
		if (!Crypto::AES_CBC_Decrypt(key.Bytes, 32, &key.Bytes[32], 16, encryptedData.data(), encryptedData.size(), decryptedData.data(), &decryptedSize))
			return false;
		decryptedData.resize(decryptedSize);
		if (decryptedSize < sizeof(Raw::RootHeader))
			return false;

		Raw::SecretHeader* header = (Raw::SecretHeader*) decryptedData.data();
		uint8_t            checksum[64];
		size_t             checksumSize = 64;
		if (!Crypto::SHA(Crypto::ESHAFunction::SHA2_512, decryptedData.data() + 64, decryptedData.size() - 64, checksum, &checksumSize))
			return false;
		if (memcmp(checksum, header->Checksum, 64) != 0)
			return false;
		size_t totalSizeRequired = sizeof(Raw::SecretHeader) + header->EntryCount * sizeof(Raw::Entry) + header->AuditCount * sizeof(Raw::SecretAudit);
		if (decryptedSize < totalSizeRequired)
			return false;

		secret.Entries.resize(header->EntryCount);
		const uint8_t* cur = decryptedData.data() + sizeof(Raw::SecretHeader);
		memcpy(secret.Entries.data(), cur, header->EntryCount * sizeof(Raw::Entry));
		cur += header->EntryCount * sizeof(Raw::Entry);
		secret.Audits.resize(header->AuditCount);
		memcpy(secret.Audits.data(), cur, header->AuditCount * sizeof(Raw::SecretAudit));
		cur += header->AuditCount * sizeof(Raw::SecretAudit);
		secret.Data.resize(decryptedData.size() - (cur - decryptedData.data()));
		memcpy(secret.Data.data(), cur, secret.Data.size());
		for (size_t i = 0; i < secret.Entries.size(); ++i)
		{
			auto& entry = secret.Entries[i];
			if (entry.Name.Offset < secret.Data.size() &&
				entry.Name.Offset + entry.Name.Length <= secret.Data.size())
				secret.Data.IncDataRef(entry.Name);
			if (entry.Value.Offset < secret.Data.size() &&
				entry.Value.Offset + entry.Value.Length <= secret.Data.size())
				secret.Data.IncDataRef(entry.Value);
		}
		for (size_t i = 0; i < secret.Entries.size(); ++i)
		{
			auto& entry                 = secret.Entries[i];
			secret.EntryIndex[entry.ID] = i;
			if (entry.Name.Offset >= secret.Data.size())
				entry.Name = secret.Data.IncDataRef(std::format("Entry {}", entry.ID));
			else if (entry.Name.Offset + entry.Name.Length > secret.Data.size())
				entry.Name.Length = secret.Data.size() - entry.Name.Offset;
			if (entry.Value.Offset >= secret.Data.size())
				entry.Value = { 0, 0 };
			else if (entry.Value.Offset + entry.Value.Length > secret.Data.size())
				entry.Value.Length = secret.Data.size() - entry.Value.Offset;
		}

		EndReadData();
		return true;
	}

	bool Root::EncryptSecret(Secret& secret)
	{
		secret.BeginWriteData();
		secret.GCClean();
		BeginReadData();
		auto itr = SecretIndex.find(secret.ID);
		if (itr == SecretIndex.end())
		{
			EndReadData();
			return false;
		}
		EndReadData();
		BeginWriteData();
		bool  keysDiffer  = memcmp(&secret.SecretKey, &RootKey, sizeof(Key)) != 0;
		auto& secretEntry = Secrets[itr->second];

		std::vector<uint8_t> decryptedData;
		decryptedData.resize(sizeof(Raw::SecretHeader) + secret.Entries.size() * sizeof(Raw::Entry) + secret.Audits.size() * sizeof(Raw::SecretAudit) + secret.Data.size());
		Raw::SecretHeader* header = (Raw::SecretHeader*) decryptedData.data();
		header->EntryCount        = secret.Entries.size();
		header->AuditCount        = secret.Audits.size();
		header->Reserved[0]       = 0;
		header->Reserved[1]       = 0;
		header->Reserved[2]       = 0;
		header->Reserved[3]       = 0;
		header->Reserved[4]       = 0;
		header->Reserved[5]       = 0;

		uint8_t* cur = decryptedData.data() + sizeof(Raw::SecretHeader);
		memcpy(cur, secret.Entries.data(), header->EntryCount * sizeof(Raw::Entry));
		cur += header->EntryCount * sizeof(Raw::Entry);
		memcpy(cur, secret.Audits.data(), header->AuditCount * sizeof(Raw::SecretAudit));
		cur += header->AuditCount * sizeof(Raw::SecretAudit);
		memcpy(cur, secret.Data.data(), secret.Data.size());

		size_t checksumSize = 64;
		if (!Crypto::SHA(Crypto::ESHAFunction::SHA2_512, decryptedData.data() + 64, decryptedData.size() - 64, header->Checksum, &checksumSize))
		{
			EndWriteData();
			return false;
		}

		size_t encryptedSize = 0;
		Crypto::AES_EncryptSize(decryptedData.size(), &encryptedSize);
		std::vector<uint8_t> encryptedData;
		encryptedData.resize(encryptedSize);
		if (!Crypto::AES_CBC_Encrypt(secret.SecretKey.Bytes, 32, &secret.SecretKey.Bytes[32], 16, decryptedData.data(), decryptedData.size(), encryptedData.data(), &encryptedSize))
		{
			EndWriteData();
			return false;
		}
		encryptedData.resize(encryptedSize);

		if (keysDiffer)
			secretEntry.Flags |= Raw::SecretEntryFlag::SeparateKey;
		if (encryptedData.size() != secretEntry.Data.Length)
		{
			RemoveSecretData(secretEntry.Data);
			secretEntry.Data = AddSecretData(ByteView { encryptedData.data(), encryptedData.size() });
		}
		else
		{
			File.seekp(SecretDataOffset + secretEntry.Data.Offset);
			File.write((const char*) encryptedData.data(), encryptedData.size());
		}
		EndWriteData();
		secret.EndWriteData();
		return true;
	}

	ByteView Root::GetByteView(const Raw::DataRef& ref)
	{
		BeginReadData();
		ByteView view = Data.GetDataView(ref);
		EndReadData();
		return view;
	}

	std::string_view Root::GetStringView(const Raw::DataRef& ref)
	{
		BeginReadData();
		ByteView view = Data.GetDataView(ref);
		EndReadData();
		return std::string_view { (const char*) view.begin(), (const char*) view.end() };
	}

	bool Root::SetSecretName(UUID uuid, std::string_view name)
	{
		BeginReadData();
		auto itr = SecretIndex.find(uuid);
		if (itr == SecretIndex.end())
		{
			EndReadData();
			return false;
		}
		EndReadData();
		BeginWriteData();
		auto& secret = Secrets[itr->second];
		Data.DecDataRef(secret.Name);
		secret.Name       = Data.IncDataRef(name);
		auto& audit       = Audits.emplace_back();
		audit.Op          = Raw::EAuditOp::RenameSecret;
		audit.Reserved[0] = 0;
		audit.Reserved[1] = 0;
		audit.Reserved[2] = 0;
		audit.Reserved[3] = 0;
		audit.Reserved[4] = 0;
		audit.Reserved[5] = 0;
		audit.Reserved[6] = 0;
		audit.Time        = Time::CurUnixTime();
		audit.SecretID    = secret.ID;
		EndWriteData();
		return true;
	}

	bool Root::GetSecretInfo(UUID uuid, Raw::SecretEntry& secretInfo)
	{
		BeginReadData();
		auto itr = SecretIndex.find(uuid);
		if (itr == SecretIndex.end())
		{
			EndReadData();
			secretInfo = {};
			return false;
		}

		auto& secret        = Secrets[itr->second];
		secretInfo.ID       = secret.ID;
		secretInfo.Flags    = secret.Flags;
		secretInfo.Name     = secret.Name;
		secretInfo.Data     = { ~0ULL, ~0ULL };
		secretInfo.Reserved = 0;
		EndReadData();
		return true;
	}

	bool Root::GetSyncInfo(UUID uuid, Raw::SyncData& syncInfo)
	{
		BeginReadData();
		auto itr = SyncIndex.find(uuid);
		if (itr == SyncIndex.end())
		{
			EndReadData();
			syncInfo = {};
			return false;
		}

		syncInfo = Syncs[itr->second];
		EndReadData();
		return true;
	}

	bool Root::FindSecrets(DataView<const std::string_view> keywords, bool (*callback)(void* userdata, const Raw::SecretEntry& secretInfo), void* userdata)
	{
		BeginReadData();
		if (keywords.empty())
		{
			for (size_t i = 0; i < Secrets.size(); ++i)
			{
				auto&            secret = Secrets[i];
				Raw::SecretEntry secretInfo;
				secretInfo.ID       = secret.ID;
				secretInfo.Flags    = secret.Flags;
				secretInfo.Name     = secret.Name;
				secretInfo.Data     = { ~0ULL, ~0ULL };
				secretInfo.Reserved = 0;
				if (!callback(userdata, secretInfo))
					break;
			}
		}
		else
		{
			// TODO(MarcasRealAccount): Implement Fuzzy Searching
			EndReadData();
			return false;
		}
		EndReadData();
		return true;
	}

	bool Root::FindSyncs(bool (*callback)(void* userdata, const Raw::SyncData& syncInfo), void* userdata)
	{
		BeginReadData();
		for (size_t i = 0; i < Syncs.size(); ++i)
		{
			if (!callback(userdata, Syncs[i]))
				break;
		}
		EndReadData();
		return true;
	}

	UUID Root::NewSecret(const Key& key)
	{
		BeginWriteData();
		uint64_t index         = Secrets.size();
		auto&    secret        = Secrets.emplace_back();
		secret.ID              = GenUniqueUUID([this](const UUID& uuid) -> bool { return SecretIndex.contains(uuid); });
		SecretIndex[secret.ID] = index;
		secret.Flags           = Raw::SecretEntryFlag::None;
		secret.Name            = Data.IncDataRef(std::format("Secret {}", secret.ID));
		secret.Data            = { ~0ULL, ~0ULL };
		secret.Reserved        = 0;

		Secret secretData;
		secretData.SecretKey = key;
		secretData.ID        = secret.ID;
		EncryptSecret(secretData); // This should really never fail... UNLESS some unforseen mistake took place with either SHA512 or AES CBC encryption.
		auto& audit       = Audits.emplace_back();
		audit.Op          = Raw::EAuditOp::CreateSecret;
		audit.Reserved[0] = 0;
		audit.Reserved[1] = 0;
		audit.Reserved[2] = 0;
		audit.Reserved[3] = 0;
		audit.Reserved[4] = 0;
		audit.Reserved[5] = 0;
		audit.Reserved[6] = 0;
		audit.Time        = Time::CurUnixTime();
		audit.SecretID    = secret.ID;
		UUID id           = secret.ID;
		EndWriteData();
		return id;
	}

	void Root::RemoveSecret(UUID uuid)
	{
		BeginReadData();
		auto itr = SecretIndex.find(uuid);
		if (itr == SecretIndex.end())
		{
			EndReadData();
			return;
		}

		if (itr->second >= Secrets.size())
		{
			EndReadData();
			BeginWriteData();
			SecretIndex.erase(itr);
			EndWriteData();
			return;
		}
		EndReadData();

		BeginWriteData();
		auto& secret = Secrets[itr->second];
		RemoveSecretData(secret.Data);
		Data.DecDataRef(secret.Name);
		Secrets.erase(Secrets.begin() + itr->second);
		for (auto& secretIndex : SecretIndex)
		{
			if (secretIndex.second > itr->second)
				--secretIndex.second;
		}
		SecretIndex.erase(itr);
		auto& audit       = Audits.emplace_back();
		audit.Op          = Raw::EAuditOp::DeleteSecret;
		audit.Reserved[0] = 0;
		audit.Reserved[1] = 0;
		audit.Reserved[2] = 0;
		audit.Reserved[3] = 0;
		audit.Reserved[4] = 0;
		audit.Reserved[5] = 0;
		audit.Reserved[6] = 0;
		audit.Time        = Time::CurUnixTime();
		audit.SecretID    = uuid;
		EndWriteData();
	}

	void Root::RemoveSync(UUID uuid)
	{
		BeginReadData();
		auto itr = SyncIndex.find(uuid);
		if (itr == SyncIndex.end())
		{
			EndReadData();
			return;
		}

		if (itr->second >= Syncs.size())
		{
			EndReadData();
			BeginWriteData();
			SyncIndex.erase(itr);
			EndWriteData();
			return;
		}

		EndReadData();
		BeginWriteData();
		auto& sync = Syncs[itr->second];
		Data.DecDataRef(sync.Path);
		switch (sync.Method)
		{
		default:
			break;
		}
		Syncs.erase(Syncs.begin() + itr->second);
		for (auto& syncIndex : SyncIndex)
		{
			if (syncIndex.second > itr->second)
				--syncIndex.second;
		}
		SyncIndex.erase(itr);
		auto& audit       = Audits.emplace_back();
		audit.Op          = Raw::EAuditOp::DeleteSync;
		audit.Reserved[0] = 0;
		audit.Reserved[1] = 0;
		audit.Reserved[2] = 0;
		audit.Reserved[3] = 0;
		audit.Reserved[4] = 0;
		audit.Reserved[5] = 0;
		audit.Reserved[6] = 0;
		audit.Time        = Time::CurUnixTime();
		audit.SecretID    = uuid;
		EndWriteData();
	}

	void Root::GCClean()
	{
		struct Userdata
		{
			Root* root;
		} userdata;
		userdata.root = this;

		Data.GCClean(
			[](void* userdata, uint64_t minOffset, uint64_t maxOffset, int64_t amount) {
				Root* root = ((Userdata*) userdata)->root;

				for (auto& secret : root->Secrets)
				{
					if (secret.Name.Offset > minOffset && secret.Name.Offset < maxOffset)
						secret.Name.Offset += amount;
				}
				for (auto& sync : root->Syncs)
				{
					if (sync.Path.Offset > minOffset && sync.Path.Offset < maxOffset)
						sync.Path.Offset += amount;
					switch (sync.Method)
					{
					default:
						break;
					}
				}
			},
			&userdata);
	}

	void Root::RemoveSecretData(const Raw::DataRef& ref)
	{
		if (ref.Offset == ~0ULL)
			return;

		BeginWriteData();
		size_t offset = ref.Offset;
		char*  buf    = new char[65536];
		File.seekp(SecretDataOffset + offset);
		offset += ref.Length;
		File.seekg(SecretDataOffset + offset);
		while (offset < SecretDataSize)
		{
			size_t toMove = std::min<size_t>(65536, SecretDataSize - offset);
			File.read(buf, toMove);
			File.write(buf, toMove);
			offset += toMove;
		}
		memset(buf, 0, 65536);
		offset = 0;
		while (offset < ref.Length)
		{
			size_t toWrite = std::min<size_t>(65536, ref.Length - offset);
			File.write(buf, toWrite);
			offset += toWrite;
		}
		delete[] buf;
		SecretDataSize -= ref.Length;
		for (size_t i = 0; i < Secrets.size(); ++i)
		{
			auto& secret2 = Secrets[i];
			if (secret2.Data.Offset > ref.Offset)
				secret2.Data.Offset -= ref.Length;
		}
		EndWriteData();
	}

	Raw::DataRef Root::AddSecretData(ByteView bytes)
	{
		BeginWriteData();
		Raw::DataRef ref { SecretDataSize, bytes.size() };
		File.seekp(SecretDataSize);
		File.write((const char*) bytes.begin(), bytes.size());
		SecretDataSize += bytes.size();
		EndWriteData();
		return ref;
	}

	bool DecryptRoot(const std::filesystem::path& filepath, Root& root, const Key& key)
	{
		root.SecretDataOffset = ~0ULL;
		root.SecretDataSize   = 0;
		root.Secrets.clear();
		root.Syncs.clear();
		root.Audits.clear();
		root.Data.clear();
		root.SecretIndex.clear();
		root.SyncIndex.clear();

		root.File = std::fstream(filepath, std::ios::binary | std::ios::in | std::ios::out | std::ios::ate);
		if (!root.File)
			return false;
		size_t filesize = root.File.tellg();
		if (filesize < sizeof(uint16_t))
			return false;
		root.Filepath = filepath;

		root.File.seekg(0);
		root.File.seekp(0);

		uint16_t version = 0;
		root.File.read((char*) &version, sizeof(version));

		switch (version)
		{
		case 1:
		{
			if (filesize < sizeof(Raw::Header))
				return false;

			Raw::Header header;
			memset(&header, 0, sizeof(header));
			root.File.seekg(0);
			root.File.read((char*) &header, sizeof(header));
			if (filesize < header.RootSize)
				return false;
			root.SecretDataOffset = header.RootSize;
			root.SecretDataSize   = filesize - header.RootSize - sizeof(Raw::Header);

			std::vector<uint8_t> encryptedRoot;
			encryptedRoot.resize(header.RootSize);
			root.File.read((char*) encryptedRoot.data(), header.RootSize);

			size_t decryptedSize = 0;
			Crypto::AES_DecryptSize(header.RootSize, &decryptedSize);
			std::vector<uint8_t> decryptedRoot;
			decryptedRoot.resize(decryptedSize);
			if (!Crypto::AES_CBC_Decrypt(key.Bytes, 32, &key.Bytes[32], 16, encryptedRoot.data(), encryptedRoot.size(), decryptedRoot.data(), &decryptedSize))
				return false;
			decryptedRoot.resize(decryptedSize);
			if (decryptedSize < sizeof(Raw::RootHeader))
				return false;

			Raw::RootHeader* rootHeader = (Raw::RootHeader*) decryptedRoot.data();
			uint8_t          checksum[64];
			size_t           checksumSize = 64;
			if (!Crypto::SHA(Crypto::ESHAFunction::SHA2_512, decryptedRoot.data() + 64, decryptedRoot.size() - 64, checksum, &checksumSize))
				return false;
			if (memcmp(checksum, rootHeader->Checksum, 64) != 0)
				return false;
			size_t totalSizeRequired = sizeof(Raw::RootHeader) + rootHeader->SecretCount * sizeof(Raw::SecretEntry) + rootHeader->SyncCount * sizeof(Raw::SyncData) + rootHeader->AuditCount * sizeof(Raw::Audit);
			if (decryptedSize < totalSizeRequired)
				return false;

			root.Secrets.resize(rootHeader->SecretCount);
			const uint8_t* cur = decryptedRoot.data() + sizeof(Raw::RootHeader);
			memcpy(root.Secrets.data(), cur, rootHeader->SecretCount * sizeof(Raw::SecretEntry));
			cur += rootHeader->SecretCount * sizeof(Raw::SecretEntry);
			root.Syncs.resize(rootHeader->SyncCount);
			memcpy(root.Syncs.data(), cur, rootHeader->SyncCount * sizeof(Raw::SyncData));
			cur += rootHeader->SyncCount * sizeof(Raw::SyncData);
			root.Audits.resize(rootHeader->AuditCount);
			memcpy(root.Audits.data(), cur, rootHeader->AuditCount * sizeof(Raw::Audit));
			cur += rootHeader->AuditCount * sizeof(Raw::Audit);
			root.Data.resize(decryptedRoot.size() - (cur - decryptedRoot.data()));
			memcpy(root.Data.data(), cur, root.Data.size());
			for (size_t i = 0; i < root.Secrets.size(); ++i)
			{
				auto& secret = root.Secrets[i];
				if (secret.Name.Offset < root.Data.size() &&
					secret.Name.Offset + secret.Name.Length <= root.Data.size())
					root.Data.IncDataRef(secret.Name);
			}
			for (size_t i = 0; i < root.Syncs.size(); ++i)
			{
				auto& sync = root.Syncs[i];
				if (sync.Path.Offset < root.Data.size() &&
					sync.Path.Offset + sync.Path.Length <= root.Data.size())
					root.Data.IncDataRef(sync.Path);
				switch (sync.Method)
				{
				default:
					break;
				}
			}

			for (size_t i = 0; i < root.Secrets.size(); ++i)
			{
				auto& secret                = root.Secrets[i];
				root.SecretIndex[secret.ID] = i;
				if (secret.Data.Offset >= root.SecretDataSize)
				{
					Secret tempSecret {};
					tempSecret.SecretKey = key;
					tempSecret.ID        = secret.ID;
					if (!root.EncryptSecret(tempSecret))
					{
						root.RemoveSecret(secret.ID);
						--i;
						continue;
					}
				}
				else if (secret.Data.Offset + secret.Data.Length > root.SecretDataSize)
				{
					// Data is partially destroyed
					// TODO(MarcasRealAccount): Ask user how they wish to solve the issue, for now just return false as if the database is broken or invalid
					return false;
				}
				if (secret.Name.Offset >= root.Data.size())
					secret.Name = root.Data.IncDataRef(std::format("Secret {}", secret.ID));
				else if (secret.Name.Offset + secret.Name.Length > root.Data.size())
					secret.Name.Length = root.Data.size() - secret.Name.Offset;
			}
			for (size_t i = 0; i < root.Syncs.size(); ++i)
			{
				// TODO(MarcasRealAccount): Perhaps tell the user the sync was broken so they know and can remedy the issue in a timely fashion. For now just remove the sync if found to be broken.
				auto& sync              = root.Syncs[i];
				root.SyncIndex[sync.ID] = i;
				if (sync.Path.Offset >= root.Data.size() ||
					sync.Path.Offset + sync.Path.Length > root.Data.size())
				{
					// Sync has missing data, we will assume this means the sync is broken and we'll just remove it, the user will need to reauthenticate but that should be fine.
					root.RemoveSync(sync.ID);
					--i;
					continue;
				}
				switch (sync.Method)
				{
				default:
					// Sync method is unknown.
					root.RemoveSync(sync.ID);
					--i;
					continue;
				}
			}
			break;
		}
		default:
			return false;
		}
		return true;
	}

	bool EncryptRoot(Root& root)
	{
		root.BeginWriteData();
		root.GCClean();

		std::vector<uint8_t> decryptedData;
		decryptedData.resize(sizeof(Raw::RootHeader) + root.Secrets.size() * sizeof(Raw::SecretEntry) + root.Syncs.size() * sizeof(Raw::SyncData) + root.Audits.size() * sizeof(Raw::Audit) + root.Data.size());

		Raw::RootHeader* rootHeader = (Raw::RootHeader*) decryptedData.data();
		rootHeader->SecretCount     = root.Secrets.size();
		rootHeader->SyncCount       = root.Syncs.size();
		rootHeader->AuditCount      = root.Audits.size();
		rootHeader->Reserved[0]     = 0;
		rootHeader->Reserved[1]     = 0;
		rootHeader->Reserved[2]     = 0;
		rootHeader->Reserved[3]     = 0;
		rootHeader->Reserved[4]     = 0;

		uint8_t* cur = decryptedData.data() + sizeof(Raw::RootHeader);
		memcpy(root.Secrets.data(), cur, rootHeader->SecretCount * sizeof(Raw::SecretEntry));
		cur += rootHeader->SecretCount * sizeof(Raw::SecretEntry);
		root.Syncs.resize(rootHeader->SyncCount);
		memcpy(root.Syncs.data(), cur, rootHeader->SyncCount * sizeof(Raw::SyncData));
		cur += rootHeader->SyncCount * sizeof(Raw::SyncData);
		root.Audits.resize(rootHeader->AuditCount);
		memcpy(root.Audits.data(), cur, rootHeader->AuditCount * sizeof(Raw::Audit));
		cur += rootHeader->AuditCount * sizeof(Raw::Audit);
		root.Data.resize(decryptedData.size() - (cur - decryptedData.data()));
		memcpy(root.Data.data(), cur, root.Data.size());

		size_t checksumSize = 64;
		if (!Crypto::SHA(Crypto::ESHAFunction::SHA2_512, decryptedData.data() + 64, decryptedData.size() - 64, rootHeader->Checksum, &checksumSize))
		{
			root.EndWriteData();
			return false;
		}

		size_t encryptedSize = 0;
		Crypto::AES_EncryptSize(decryptedData.size(), &encryptedSize);
		std::vector<uint8_t> encryptedData;
		encryptedData.resize(encryptedSize);
		if (!Crypto::AES_CBC_Encrypt(&root.RootKey, 32, &root.RootKey.Bytes[32], 16, decryptedData.data(), decryptedData.size(), encryptedData.data(), &encryptedSize))
		{
			root.EndWriteData();
			return false;
		}
		encryptedData.resize(encryptedSize);
		Raw::Header header;
		header.Version     = 1;
		header.Reserved[0] = 0;
		header.Reserved[1] = 0;
		header.Reserved[2] = 0;
		header.RootSize    = encryptedData.size();
		root.File.seekp(0);
		root.File.write((const char*) &header, sizeof(header));
		if (sizeof(Raw::Header) + encryptedData.size() < root.SecretDataOffset)
		{
			root.File.write((const char*) encryptedData.data(), encryptedData.size());
			size_t shiftAmount = root.SecretDataOffset - (sizeof(Raw::Header) + encryptedData.size());

			char* buf = new char[65536];
			root.File.seekg(root.SecretDataOffset);
			size_t offset = 0;
			while (offset < root.SecretDataSize)
			{
				size_t toMove = std::min<size_t>(65536, root.SecretDataSize - offset);
				root.File.read(buf, toMove);
				root.File.write(buf, toMove);
				offset += toMove;
			}
			memset(buf, 0, 65536);
			offset = 0;
			while (offset < shiftAmount)
			{
				size_t toWrite = std::min<size_t>(65536, shiftAmount - offset);
				root.File.write(buf, toWrite);
				offset += toWrite;
			}
			delete[] buf;
			root.SecretDataOffset = sizeof(Raw::Header) + encryptedData.size();
			std::filesystem::resize_file(root.Filepath, root.SecretDataOffset + root.SecretDataSize);
		}
		else if (sizeof(Raw::Header) + encryptedData.size() > root.SecretDataOffset)
		{
			size_t shiftAmount = (sizeof(Raw::Header) + encryptedData.size()) - root.SecretDataOffset;

			char* buf = new char[65536];
			if (root.SecretDataSize < 65536)
			{
				root.File.seekp(sizeof(Raw::Header) + encryptedData.size());
				root.File.seekg(root.SecretDataOffset);
				root.File.read(buf, root.SecretDataSize);
				root.File.write(buf, root.SecretDataSize);
			}
			else
			{
				size_t offset = root.SecretDataSize;
				while (offset >= 0)
				{
					size_t toMove = std::min<size_t>(65536, offset);
					offset       -= toMove;
					root.File.seekg(root.SecretDataOffset + offset);
					root.File.seekp(root.SecretDataOffset + offset + shiftAmount);
					root.File.read(buf, toMove);
					root.File.write(buf, toMove);
				}
			}
			delete[] buf;
			root.SecretDataOffset = sizeof(Raw::Header) + encryptedData.size();

			root.File.seekp(sizeof(Raw::Header));
			root.File.write((const char*) encryptedData.data(), encryptedData.size());
		}

		root.EndWriteData();
		return true;
	}
} // namespace Database