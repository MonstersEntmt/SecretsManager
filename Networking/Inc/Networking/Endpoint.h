#pragma once

#include "Address.h"

#include <string>
#include <variant>

namespace Networking
{
	struct AddressEndpoint
	{
	public:
		constexpr AddressEndpoint()
			: Port(0) {}
		constexpr AddressEndpoint(Address address, uint16_t port)
			: Addr(address),
			  Port(port) {}

		constexpr bool          IsIPv4() const { return Addr.IsIPv4(); }
		constexpr bool          IsIPv6() const { return Addr.IsIPv6(); }
		constexpr bool          IsPath() const { return false; }
		constexpr bool          IsValid() const { return Addr.IsValid(); }
		constexpr EEndpointType GetType() const { return Addr.GetType(); }

		constexpr bool ToString(char* buf, size_t bufSize) const
		{
			size_t portSize = 2;
			if (Port >= 10000)
				portSize = 5;
			else if (Port >= 1000)
				portSize = 4;
			else if (Port >= 100)
				portSize = 3;
			else if (Port >= 10)
				portSize = 2;
			else
				portSize = 1;
			size_t offset = 0;
			if (IsIPv6())
			{
				if (bufSize < 1)
					return false;
				if (!Addr.ToString(buf + 1, bufSize - 1))
					return false;
				size_t addrEnd = strlen(buf + 1) + 1;
				if (bufSize < (addrEnd + 1 + portSize))
					return false;
				buf[addrEnd] = ']';
				offset       = addrEnd + 1;
			}
			else
			{
				if (!Addr.ToString(buf, bufSize))
					return false;
				size_t addrEnd = strlen(buf);
				if (bufSize < (addrEnd + portSize))
					return false;
				offset = addrEnd;
			}
			buf[offset++] = ':';
			uint16_t v    = Port;
			if (v >= 10000)
			{
				buf[offset + 5] = '\0';
				buf[offset + 4] = '0' + (v % 10);
				v              /= 10;
				buf[offset + 3] = '0' + (v % 10);
				v              /= 10;
				buf[offset + 2] = '0' + (v % 10);
				v              /= 10;
				buf[offset + 1] = '0' + (v % 10);
				v              /= 10;
				buf[offset + 0] = '0' + (v % 10);
			}
			else if (v >= 1000)
			{
				buf[offset + 4] = '\0';
				buf[offset + 3] = '0' + (v % 10);
				v              /= 10;
				buf[offset + 2] = '0' + (v % 10);
				v              /= 10;
				buf[offset + 1] = '0' + (v % 10);
				v              /= 10;
				buf[offset + 0] = '0' + (v % 10);
			}
			else if (v >= 100)
			{
				buf[offset + 3] = '\0';
				buf[offset + 2] = '0' + (v % 10);
				v              /= 10;
				buf[offset + 1] = '0' + (v % 10);
				v              /= 10;
				buf[offset + 0] = '0' + (v % 10);
			}
			else if (v >= 10)
			{
				buf[offset + 2] = '\0';
				buf[offset + 1] = '0' + (v % 10);
				v              /= 10;
				buf[offset + 0] = '0' + (v % 10);
			}
			else
			{
				buf[offset + 1] = '\0';
				buf[offset + 0] = '0' + (uint8_t) v;
			}
			return true;
		}

		constexpr bool operator==(AddressEndpoint other) const { return Addr == other.Addr && Port == other.Port; }
		constexpr bool operator!=(AddressEndpoint other) const { return !(*this == other); }

	public:
		Address  Addr;
		uint16_t Port;
	};

	struct PathEndpoint
	{
	public:
		constexpr PathEndpoint() {}
		constexpr PathEndpoint(std::string_view path)
			: Path(path) {}
		constexpr PathEndpoint(const PathEndpoint& copy)
			: Path(copy.Path) {}
		constexpr PathEndpoint(PathEndpoint&& move) noexcept
			: Path(std::move(move.Path)) {}

		constexpr PathEndpoint& operator=(const PathEndpoint& copy)
		{
			Path = copy.Path;
			return *this;
		}

		constexpr PathEndpoint& operator=(PathEndpoint&& move) noexcept
		{
			Path = std::move(move.Path);
			return *this;
		}

		constexpr bool          IsIPv4() const { return false; }
		constexpr bool          IsIPv6() const { return false; }
		constexpr bool          IsPath() const { return true; }
		constexpr bool          IsValid() const { return !Path.empty(); }
		constexpr EEndpointType GetType() const { return EEndpointType::Path; }

		constexpr bool ToString(char* buf, size_t bufSize) const
		{
			if (bufSize <= Path.size())
				return false;
			memcpy(buf, Path.c_str(), Path.size());
			buf[Path.size()] = '\0';
			return true;
		}

		constexpr bool operator==(const PathEndpoint& other) const { return Path == other.Path; }
		constexpr bool operator!=(const PathEndpoint& other) const { return Path != other.Path; }

	public:
		std::string Path;
	};

	struct Endpoint
	{
	public:
		static Endpoint    ResolveFromHost(std::string_view node, std::string_view service, EEndpointType type = EEndpointType::Both);
		static std::string ToHost(const Endpoint& endpoint);

	public:
		constexpr Endpoint()
			: Value((size_t) 0) {}
		constexpr Endpoint(Address address, uint16_t port)
			: Value(AddressEndpoint(address, port)) {}
		constexpr Endpoint(std::string_view path)
			: Value(PathEndpoint(path)) {}
		constexpr Endpoint(const Endpoint& copy)
			: Value(copy.Value) {}
		constexpr Endpoint(Endpoint&& move) noexcept
			: Value(std::move(move.Value)) {}
		Endpoint(std::string_view node, std::string_view service, EEndpointType type = EEndpointType::Both)
			: Endpoint(ResolveFromHost(node, service, type)) {}

		constexpr Endpoint& operator=(AddressEndpoint address)
		{
			Value = address;
			return *this;
		}
		constexpr Endpoint& operator=(std::string_view path)
		{
			Value = PathEndpoint(path);
			return *this;
		}
		constexpr Endpoint& operator=(const PathEndpoint& path)
		{
			Value = path;
			return *this;
		}
		constexpr Endpoint& operator=(PathEndpoint&& path) noexcept
		{
			Value = std::move(path);
			return *this;
		}
		constexpr Endpoint& operator=(const Endpoint& endpoint)
		{
			Value = endpoint.Value;
			return *this;
		}
		constexpr Endpoint& operator=(Endpoint&& endpoint) noexcept
		{
			Value = std::move(endpoint.Value);
			return *this;
		}

		constexpr bool IsIPv4() const { return GetType() == EEndpointType::IPv4; }
		constexpr bool IsIPv6() const { return GetType() == EEndpointType::IPv6; }
		constexpr bool IsPath() const { return GetType() == EEndpointType::Path; }
		constexpr bool IsValid() const
		{
			switch (Value.index())
			{
			case 1: return GetAddress().IsValid();
			case 2: return GetPath().IsValid();
			default: return false;
			}
		}
		constexpr EEndpointType GetType() const
		{
			switch (Value.index())
			{
			case 1: return GetAddress().GetType();
			case 2: return GetPath().GetType();
			default: return EEndpointType::Unknown;
			}
		}

		constexpr bool ToString(char* buf, size_t bufSize) const
		{
			switch (Value.index())
			{
			case 1: return GetAddress().ToString(buf, bufSize);
			case 2: return GetPath().ToString(buf, bufSize);
			default: return false;
			}
		}
		std::string ToHost() const { return Endpoint::ToHost(*this); }

		constexpr bool operator==(const Endpoint& other) const
		{
			if (Value.index() != other.Value.index())
				return false;

			switch (Value.index())
			{
			case 1: return GetAddress() == other.GetAddress();
			case 2: return GetPath() == other.GetPath();
			default: return false;
			}
		}
		constexpr bool operator!=(const Endpoint& other) const
		{
			if (Value.index() != other.Value.index())
				return true;

			switch (Value.index())
			{
			case 1: return GetAddress() != other.GetAddress();
			case 2: return GetPath() != other.GetPath();
			default: return false;
			}
		}

		AddressEndpoint&       GetAddress() { return std::get<AddressEndpoint>(Value); }
		const AddressEndpoint& GetAddress() const { return std::get<AddressEndpoint>(Value); }
		PathEndpoint&          GetPath() { return std::get<PathEndpoint>(Value); }
		const PathEndpoint&    GetPath() const { return std::get<PathEndpoint>(Value); }

	public:
		std::variant<size_t, AddressEndpoint, PathEndpoint> Value;
	};
} // namespace Networking