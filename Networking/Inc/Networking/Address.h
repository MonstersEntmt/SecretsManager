#pragma once

#include <cstdint>

namespace Networking
{
	enum class EEndpointType
	{
		Both,
		IPv4,
		IPv6,
		Path,
		Unknown
	};

	union IPv4Address
	{
	public:
		constexpr IPv4Address()
			: Value(0U) {}
		constexpr IPv4Address(uint32_t address)
			: Value(address) {}
		constexpr IPv4Address(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3)
			: Value(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) {}

		constexpr bool operator==(IPv4Address other) const { return Value == other.Value; }
		constexpr bool operator!=(IPv4Address other) const { return Value != other.Value; }

		uint32_t Value;
	};

	union IPv6Address
	{
	public:
		constexpr IPv6Address()
			: Segments { 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U } {}
		constexpr IPv6Address(uint32_t ipv4, uint16_t s3, uint16_t s4, uint16_t s5, uint16_t s6, uint16_t s7)
			: IPv6Address(ipv4 & 0xFFFF, (ipv4 >> 16) & 0xFFFF, 0xFFFF, s3, s4, s5, s6, s7) {}
		constexpr IPv6Address(uint16_t s0, uint16_t s1, uint16_t s2, uint16_t s3, uint16_t s4, uint16_t s5, uint16_t s6, uint16_t s7)
			: Segments { s0, s1, s2, s3, s4, s5, s6, s7 } {}
		constexpr IPv6Address(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3, uint8_t b4, uint8_t b5, uint8_t b6, uint8_t b7, uint8_t b8, uint8_t b9, uint8_t b10, uint8_t b11, uint8_t b12, uint8_t b13, uint8_t b14, uint8_t b15)
			: IPv6Address(b0 | (b1 << 8), b2 | (b3 << 8), b4 | (b5 << 8), b6 | (b7 << 8), b8 | (b9 << 8), b10 | (b11 << 8), b12 | (b13 << 8), b14 | (b15 << 8)) {}

		constexpr bool operator==(IPv6Address other) const
		{
			for (size_t i = 0; i < 8; ++i)
			{
				if (Segments[i] != other.Segments[i])
					return false;
			}
			return true;
		}
		constexpr bool operator!=(IPv6Address other) const { return !(*this == other); }

		uint16_t Segments[8];
	};

	union Address
	{
	public:
		constexpr Address()
			: IPv6() {}
		constexpr Address(IPv4Address address)
			: IPv6(address.Value, 0U, 0U, 0U, 0U, 0U) {}
		constexpr Address(IPv6Address address)
			: IPv6(address) {}

		constexpr bool IsIPv4() const { return GetType() == EEndpointType::IPv4; }
		constexpr bool IsIPv6() const { return GetType() == EEndpointType::IPv6; }
		constexpr bool IsValid() const
		{
			for (size_t i = 0; i < 8; ++i)
			{
				if (IPv6.Segments[i] != 0)
					return true;
			}
			return false;
		}
		constexpr EEndpointType GetType() const
		{
			for (size_t i = 3; i < 8; ++i)
			{
				if (IPv6.Segments[i])
					return EEndpointType::IPv6;
			}
			return IPv6.Segments[2] == 0xFFFF ? EEndpointType::IPv4 : EEndpointType::IPv6;
		}

		constexpr bool ToString(char* buf, size_t bufSize) const
		{
			switch (GetType())
			{
			case EEndpointType::IPv4:
			{
				uint32_t ipv4Value = IPv6.Segments[0] | (IPv6.Segments[1] << 16);
				uint8_t  bytes[4];
				bytes[0] = ipv4Value & 0xFF;
				bytes[1] = (ipv4Value >> 8) & 0xFF;
				bytes[2] = (ipv4Value >> 16) & 0xFF;
				bytes[3] = (ipv4Value >> 24) & 0xFF;

				uint8_t offs[4];
				uint8_t curOff = 0;
				for (size_t i = 0; i < 4; ++i)
				{
					offs[i] = curOff;
					if (bytes[i] >= 100)
						curOff += 3;
					else if (bytes[i] >= 10)
						curOff += 2;
					else
						curOff += 1;
					if (i < 3)
						++curOff;
				}
				if (bufSize <= curOff)
					return false;
				buf[offs[1] - 1] = '.';
				buf[offs[2] - 1] = '.';
				buf[offs[3] - 1] = '.';
				buf[curOff]      = '\0';
				for (size_t i = 0; i < 4; ++i)
				{
					uint8_t v = bytes[i];
					uint8_t j = offs[i];
					if (v >= 100)
					{
						buf[j + 2] = '0' + (v % 10);
						v         /= 10;
						buf[j + 1] = '0' + (v % 10);
						v         /= 10;
						buf[j]     = '0' + (v % 10);
					}
					else if (v >= 10)
					{
						buf[j + 1] = '0' + (v % 10);
						v         /= 10;
						buf[j]     = '0' + (v % 10);
					}
					else
					{
						buf[j] = '0' + v;
					}
				}
				return true;
			}
			case EEndpointType::IPv6:
			{
				uint16_t segs[8];
				for (uint8_t i = 0; i < 8; ++i)
					segs[i] = IPv6.Segments[i];

				uint8_t offs[8];
				uint8_t curOff   = 0;
				uint8_t gapStart = 8;
				uint8_t gapEnd   = 8;
				uint8_t gapSegs  = 0;
				uint8_t start    = 0;
				uint8_t segments = 0;
				for (uint8_t i = 0; i < 8; ++i)
				{
					offs[i] = curOff;
					if (segs[i] >= 0x1000)
						curOff += 4;
					else if (segs[i] >= 0x100)
						curOff += 3;
					else if (segs[i] >= 0x10)
						curOff += 2;
					else
						curOff += 1;
					if (i < 7)
						++curOff;

					if (segs[i] != 0)
					{
						if (segments > 0 && gapSegs < segments)
						{
							gapStart = start;
							gapEnd   = i;
							gapSegs  = segments;
						}
						start    = i + 1;
						segments = 0;
					}
					else
					{
						++segments;
					}
				}
				if (segments > 0 && gapSegs < segments)
				{
					gapStart = start;
					gapEnd   = 8;
					gapSegs  = segments;
				}
				uint8_t deltaOff = gapEnd < 7 ? offs[gapEnd + 1] - (offs[gapStart] + 1) : 0;
				for (uint8_t i = gapEnd + 1; i < 8; ++i)
					offs[i] -= deltaOff;
				curOff -= deltaOff;
				if (bufSize <= curOff)
					return false;
				constexpr char c_HexDigits[] = "0123456789abcdef";
				buf[curOff]                  = '\0';
				for (uint8_t i = 0; i < 8; ++i)
				{
					if (i >= gapStart && i < gapEnd)
						continue;

					uint8_t off = offs[i];
					if (segs[i] >= 0x1000)
					{
						buf[off]     = c_HexDigits[(segs[i] >> 12) & 0xF];
						buf[off + 1] = c_HexDigits[(segs[i] >> 8) & 0xF];
						buf[off + 2] = c_HexDigits[(segs[i] >> 4) & 0xF];
						buf[off + 3] = c_HexDigits[segs[i] & 0xF];
						off         += 4;
					}
					else if (segs[i] >= 0x100)
					{
						buf[off]     = c_HexDigits[(segs[i] >> 8) & 0xF];
						buf[off + 1] = c_HexDigits[(segs[i] >> 4) & 0xF];
						buf[off + 2] = c_HexDigits[segs[i] & 0xF];
						off         += 3;
					}
					else if (segs[i] >= 0x10)
					{
						buf[off]     = c_HexDigits[(segs[i] >> 4) & 0xF];
						buf[off + 1] = c_HexDigits[segs[i] & 0xF];
						off         += 2;
					}
					else
					{
						buf[off] = c_HexDigits[segs[i] & 0xF];
						off     += 1;
					}
					if (i < 7)
						buf[off] = ':';
				}
				if (gapStart < 8)
					buf[offs[gapStart]] = ':';
				return true;
			}
			default:
				return false;
			}
		}

		constexpr bool operator==(Address other) const { return IPv6 == other.IPv6; }
		constexpr bool operator!=(Address other) const { return IPv6 != other.IPv6; }

		IPv4Address IPv4;
		IPv6Address IPv6;
	};
} // namespace Networking