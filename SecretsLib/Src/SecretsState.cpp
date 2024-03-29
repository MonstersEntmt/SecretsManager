#include "SecretsState.h"

bool SecretsState::HasDB() const
{
	return m_Root.IsDecrypted();
}

bool SecretsState::NewDB(const std::filesystem::path& dbPath, const Database::Key& key)
{
	if (HasDB() &&
		!CloseDB())
		return false;

	m_Root.Reset();
	m_Root.File = std::fstream(dbPath, std::ios::binary | std::ios::in | std::ios::out);
	if (!m_Root.File)
		return false;
	m_Root.Filepath = dbPath;
	m_Root.RootKey  = key;
	m_DecryptedSecret.Reset();
	return Database::EncryptRoot(m_Root);
}

bool SecretsState::OpenDB(const std::filesystem::path& dbPath, const Database::Key& key)
{
	if (HasDB() &&
		!CloseDB())
		return false;

	return Database::DecryptRoot(dbPath, m_Root, key);
}

bool SecretsState::SaveDB()
{
	if (!HasDB() ||
		!LockSecret() ||
		!SyncDB())
		return false;

	return Database::EncryptRoot(m_Root);
}

bool SecretsState::CloseDB()
{
	if (!SaveDB())
		return false;
	m_Root.Reset();
	return true;
}

bool SecretsState::GetSync(UUID uuid, SyncInfo& syncInfo)
{
	if (!HasDB())
		return false;

	m_Root.BeginReadData();
	Database::Raw::SyncData databaseSyncInfo;
	if (!m_Root.GetSyncInfo(uuid, databaseSyncInfo))
	{
		m_Root.EndReadData();
		return false;
	}
	syncInfo.ID   = databaseSyncInfo.ID;
	syncInfo.Path = m_Root.GetStringView(databaseSyncInfo.Path);
	switch (databaseSyncInfo.Method)
	{
	default:
		syncInfo.Method = ESyncMethod::Unknown;
		break;
	}
	m_Root.EndReadData();
	return true;
}

bool SecretsState::SyncDB()
{
	if (!HasDB())
		return false;
	return true;
}

bool SecretsState::CreateSecret(const Database::Key& key)
{
	if (!HasDB())
		return false;

	UUID uuid = m_Root.NewSecret(key);
	return UnlockSecret(uuid, key);
}

bool SecretsState::DeleteSecret(UUID uuid)
{
	if (!HasDB())
		return false;
	if (m_DecryptedSecret.ID == uuid && !LockSecret())
		return false;
	m_Root.RemoveSecret(uuid);
	return true;
}

bool SecretsState::GetSecret(UUID uuid, SecretInfo& secretInfo)
{
	if (!HasDB())
		return false;

	m_Root.BeginReadData();
	Database::Raw::SecretEntry databaseSecretInfo;
	if (!m_Root.GetSecretInfo(uuid, databaseSecretInfo))
	{
		m_Root.EndReadData();
		return false;
	}
	secretInfo.ID    = databaseSecretInfo.ID;
	secretInfo.Flags = databaseSecretInfo.Flags; // TODO(MarcasRealAccount): Ensure proper conversion here.
	secretInfo.Name  = m_Root.GetStringView(databaseSecretInfo.Name);
	m_Root.EndReadData();
	return true;
}

bool SecretsState::GetSecretEntry(UUID uuid, SecretEntryInfo& entryInfo)
{
	if (!HasDB() ||
		!HasUnlockedSecret())
		return false;

	m_DecryptedSecret.BeginReadData();
	Database::Raw::Entry databaseEntryInfo;
	if (!m_DecryptedSecret.GetEntryInfo(uuid, databaseEntryInfo))
	{
		m_DecryptedSecret.EndReadData();
		return false;
	}
	entryInfo.ID    = databaseEntryInfo.ID;
	entryInfo.Name  = m_DecryptedSecret.GetStringView(databaseEntryInfo.Name);
	entryInfo.Value = m_DecryptedSecret.GetStringView(databaseEntryInfo.Value);
	m_DecryptedSecret.EndReadData();
	return true;
}

bool SecretsState::UnlockSecret(UUID uuid, const Database::Key& key)
{
	if (!HasDB() ||
		!LockSecret())
		return false;

	return m_Root.DecryptSecret(m_DecryptedSecret, uuid, key);
}

bool SecretsState::SaveSecret()
{
	if (!HasDB())
		return false;
	if (!HasUnlockedSecret())
		return true;

	return m_Root.EncryptSecret(m_DecryptedSecret);
}

bool SecretsState::LockSecret()
{
	if (!SaveSecret())
		return false;
	m_DecryptedSecret.Reset();
	return true;
}

bool SecretsState::HasUnlockedSecret() const
{
	return m_DecryptedSecret.IsDecrypted();
}

bool SecretsState::SetSecretName(UUID uuid, std::string_view name)
{
	if (!HasDB())
		return false;

	return m_Root.SetSecretName(uuid, name);
}

bool SecretsState::SetSecretEntryName(UUID uuid, std::string_view name)
{
	if (!HasDB() ||
		!HasUnlockedSecret())
		return false;

	return m_DecryptedSecret.SetEntryName(uuid, name);
}

bool SecretsState::SetSecretEntryValue(UUID uuid, std::string_view value)
{
	if (!HasDB() ||
		!HasUnlockedSecret())
		return false;

	return m_DecryptedSecret.SetEntryValue(uuid, value);
}

bool SecretsState::FindSecrets(DataView<const std::string_view> keywords, bool (*callback)(void* userdata, const SecretInfo& secretInfo), void* userdata)
{
	if (!HasDB() ||
		!callback)
		return false;

	struct PassThroughUserdata
	{
		bool            (*Callback)(void* userdata, const SecretInfo& secretInfo);
		void*           Userdata;
		Database::Root* Root;
		SecretInfo      Info;
	} user;
	user.Callback = callback;
	user.Userdata = userdata;
	user.Root     = &m_Root;

	return m_Root.FindSecrets(
		keywords,
		[](void* userdata, const Database::Raw::SecretEntry& databaseSecretInfo) -> bool {
			PassThroughUserdata* passThrough = (PassThroughUserdata*) userdata;
			passThrough->Info.ID             = databaseSecretInfo.ID;
			passThrough->Info.Flags          = databaseSecretInfo.Flags; // TODO(MarcasRealAccount): Ensure proper conversion here.
			passThrough->Info.Name           = passThrough->Root->GetStringView(databaseSecretInfo.Name);
			return passThrough->Callback(passThrough->Userdata, passThrough->Info);
		},
		&user);
}

bool SecretsState::FindSecretEntries(DataView<const std::string_view> keywords, bool (*callback)(void* userdata, const SecretEntryInfo& entryInfo), void* userdata)
{
	if (!HasDB() ||
		!HasUnlockedSecret() ||
		!callback)
		return false;

	struct PassThroughUserdata
	{
		bool              (*Callback)(void* userdata, const SecretEntryInfo& entryInfo);
		void*             Userdata;
		Database::Secret* Secret;
		SecretEntryInfo   Info;
	} user;
	user.Callback = callback;
	user.Userdata = userdata;
	user.Secret   = &m_DecryptedSecret;

	return m_DecryptedSecret.FindEntries(
		keywords,
		[](void* userdata, const Database::Raw::Entry& databaseEntryInfo) -> bool {
			PassThroughUserdata* passThrough = (PassThroughUserdata*) userdata;
			passThrough->Info.ID             = databaseEntryInfo.ID;
			passThrough->Info.Name           = passThrough->Secret->GetStringView(databaseEntryInfo.Name);
			passThrough->Info.Value          = passThrough->Secret->GetStringView(databaseEntryInfo.Value);
			return passThrough->Callback(passThrough->Userdata, passThrough->Info);
		},
		&user);
}

bool SecretsState::FindSyncs(bool (*callback)(void* userdata, const SyncInfo& syncInfo), void* userdata)
{
	if (!HasDB() ||
		!callback)
		return false;

	struct PassThroughUserdata
	{
		bool            (*Callback)(void* userdata, const SyncInfo& syncInfo);
		void*           Userdata;
		Database::Root* Root;
		SyncInfo        Info;
	} user;
	user.Callback = callback;
	user.Userdata = userdata;
	user.Root     = &m_Root;

	return m_Root.FindSyncs(
		[](void* userdata, const Database::Raw::SyncData& databaseSyncInfo) -> bool {
			PassThroughUserdata* passThrough = (PassThroughUserdata*) userdata;
			passThrough->Info.ID             = databaseSyncInfo.ID;
			passThrough->Info.Path           = passThrough->Root->GetStringView(databaseSyncInfo.Path);
			switch (databaseSyncInfo.Method)
			{
			default:
				passThrough->Info.Method = ESyncMethod::Unknown;
				break;
			}
			return passThrough->Callback(passThrough->Userdata, passThrough->Info);
		},
		&user);
}

void SecretsState::GCClean()
{
	if (!HasDB())
		return;
	if (HasUnlockedSecret())
		m_DecryptedSecret.GCClean();
	m_Root.GCClean();
}