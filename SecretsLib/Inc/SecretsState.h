#pragma once

#include "SecretsDB.h"

using SecretInfoFlags = uint64_t;

namespace SecretInfoFlag
{
	static constexpr SecretInfoFlags None        = 0x0000'0000'0000'0000ULL;
	static constexpr SecretInfoFlags SeparateKey = 0x0000'0000'0000'0001ULL;
} // namespace SecretInfoFlag

struct SecretInfo
{
	UUID            ID;
	SecretInfoFlags Flags;
	std::string     Name;
};

struct SecretEntryInfo
{
	UUID        ID;
	std::string Name;
	std::string Value;
};

enum class ESyncMethod : uint8_t
{
	// OneDrive,
	Unknown = 0xFF
};

struct SyncInfo
{
	UUID        ID;
	std::string Path;
	ESyncMethod Method;
};

class SecretsState
{
public:
	bool HasDB() const;
	bool NewDB(const std::filesystem::path& dbPath, const Database::Key& key);
	bool OpenDB(const std::filesystem::path& dbPath, const Database::Key& key);
	bool SaveDB();
	bool CloseDB();

	// TODO(MarcasRealAccount): Add sync functions
	bool GetSync(UUID uuid, SyncInfo& syncInfo);
	bool SyncDB();

	bool CreateSecret(const Database::Key& key);
	bool CreateSecret() { return CreateSecret(m_Root.RootKey); }
	bool DeleteSecret(UUID uuid);
	bool GetSecret(UUID uuid, SecretInfo& secretInfo);
	bool GetSecretEntry(UUID uuid, SecretEntryInfo& entryInfo);
	bool UnlockSecret(UUID uuid) { return UnlockSecret(uuid, m_Root.RootKey); }
	bool UnlockSecret(UUID uuid, const Database::Key& key);
	bool SaveSecret();
	bool LockSecret();
	bool HasUnlockedSecret() const;

	bool SetSecretName(UUID uuid, std::string_view name);
	bool SetSecretEntryName(UUID uuid, std::string_view name);
	bool SetSecretEntryValue(UUID uuid, std::string_view value);

	bool FindSecrets(DataView<const std::string_view> keywords, bool (*callback)(void* userdata, const SecretInfo& secretInfo), void* userdata);
	bool FindSecretEntries(DataView<const std::string_view> keywords, bool (*callback)(void* userdata, const SecretEntryInfo& entryInfo), void* userdata);
	bool FindSyncs(bool (*callback)(void* userdata, const SyncInfo& syncInfo), void* userdata);

	void GCClean();

private:
	Database::Root   m_Root;
	Database::Secret m_DecryptedSecret;
};