#pragma once

#include <cstdint>

#include <bit>
#include <format>
#include <functional>
#include <string_view>

union UUID
{
	struct Ints
	{
		uint64_t Low, High;
	} Ints;
	struct Fields
	{
		uint32_t TimeLow;
		uint16_t TimeMid;
		uint16_t TimeHighAndVersion;
		uint8_t  ClockSeqAndReserved;
		uint8_t  ClockSeqLow;
		uint8_t  Node[6];
	} Fields;

	constexpr UUID() noexcept
	{
		Ints.Low  = 0;
		Ints.High = 0;
	}

	constexpr UUID(uint64_t low, uint64_t high) noexcept
	{
		Ints.Low  = low;
		Ints.High = high;
	}

	constexpr UUID(uint32_t timeLow, uint16_t timeMid, uint16_t timeHighAndVersion, uint8_t clockSeqAndReserved, uint8_t clockSeqLow, uint8_t node0, uint8_t node1, uint8_t node2, uint8_t node3, uint8_t node4, uint8_t node5) noexcept
	{
		Fields.TimeLow             = timeLow;
		Fields.TimeMid             = timeMid;
		Fields.TimeHighAndVersion  = timeHighAndVersion;
		Fields.ClockSeqAndReserved = clockSeqAndReserved;
		Fields.ClockSeqLow         = clockSeqLow;
		Fields.Node[0]             = node0;
		Fields.Node[1]             = node1;
		Fields.Node[2]             = node2;
		Fields.Node[3]             = node3;
		Fields.Node[4]             = node4;
		Fields.Node[5]             = node5;
	}

	constexpr UUID(std::string_view str) noexcept
	{
		if (str.size() < 36 || str[8] != '-' || str[13] != '-' || str[18] != '-' || str[23] != '-')
		{
			Ints.Low  = 0;
			Ints.High = 0;
			return;
		}

		auto getHexDigit = [](char c, uint8_t& value) constexpr -> bool {
			if (c >= '0' && c <= '9')
			{
				value = c - '0';
				return true;
			}
			if (c >= 'A' && c <= 'F')
			{
				value = 10 + (c - 'A');
				return true;
			}
			if (c >= 'a' && c <= 'f')
			{
				value = 10 + (c - 'a');
				return true;
			}
			return false;
		};

		Ints.Low  = 0;
		Ints.High = 0;
		uint8_t v = 0;
		if (!getHexDigit(str[0], v))
			return;
		Fields.TimeLow = v << 28;
		if (!getHexDigit(str[1], v))
			return;
		Fields.TimeLow |= v << 24;
		if (!getHexDigit(str[2], v))
			return;
		Fields.TimeLow |= v << 20;
		if (!getHexDigit(str[3], v))
			return;
		Fields.TimeLow |= v << 16;
		if (!getHexDigit(str[4], v))
			return;
		Fields.TimeLow |= v << 12;
		if (!getHexDigit(str[5], v))
			return;
		Fields.TimeLow |= v << 8;
		if (!getHexDigit(str[6], v))
			return;
		Fields.TimeLow |= v << 4;
		if (!getHexDigit(str[7], v))
			return;
		Fields.TimeLow |= v;

		if (!getHexDigit(str[9], v))
			return;
		Fields.TimeMid = v << 12;
		if (!getHexDigit(str[10], v))
			return;
		Fields.TimeMid |= v << 8;
		if (!getHexDigit(str[11], v))
			return;
		Fields.TimeMid |= v << 4;
		if (!getHexDigit(str[12], v))
			return;
		Fields.TimeMid |= v;

		if (!getHexDigit(str[14], v))
			return;
		Fields.TimeHighAndVersion = v << 12;
		if (!getHexDigit(str[15], v))
			return;
		Fields.TimeHighAndVersion |= v << 8;
		if (!getHexDigit(str[16], v))
			return;
		Fields.TimeHighAndVersion |= v << 4;
		if (!getHexDigit(str[17], v))
			return;
		Fields.TimeHighAndVersion |= v;

		if (!getHexDigit(str[19], v))
			return;
		Fields.ClockSeqAndReserved = v << 4;
		if (!getHexDigit(str[20], v))
			return;
		Fields.ClockSeqAndReserved |= v;
		if (!getHexDigit(str[21], v))
			return;
		Fields.ClockSeqLow = v << 4;
		if (!getHexDigit(str[22], v))
			return;
		Fields.ClockSeqLow |= v;

		if (!getHexDigit(str[24], v))
			return;
		Fields.Node[0] = v << 4;
		if (!getHexDigit(str[25], v))
			return;
		Fields.Node[0] |= v;

		if (!getHexDigit(str[26], v))
			return;
		Fields.Node[1] = v << 4;
		if (!getHexDigit(str[27], v))
			return;
		Fields.Node[1] |= v;

		if (!getHexDigit(str[28], v))
			return;
		Fields.Node[2] = v << 4;
		if (!getHexDigit(str[29], v))
			return;
		Fields.Node[2] |= v;

		if (!getHexDigit(str[30], v))
			return;
		Fields.Node[3] = v << 4;
		if (!getHexDigit(str[31], v))
			return;
		Fields.Node[3] |= v;

		if (!getHexDigit(str[32], v))
			return;
		Fields.Node[4] = v << 4;
		if (!getHexDigit(str[33], v))
			return;
		Fields.Node[4] |= v;

		if (!getHexDigit(str[34], v))
			return;
		Fields.Node[5] = v << 4;
		if (!getHexDigit(str[35], v))
			return;
		Fields.Node[5] |= v;
	}

	constexpr UUID(const UUID& copy) noexcept
	{
		Ints.Low  = copy.Ints.Low;
		Ints.High = copy.Ints.High;
	}

	constexpr bool ToString(char* buf, size_t bufSize) const noexcept
	{
		constexpr char c_HexDigits[] = "0123456789abcdef";
		if (!buf || bufSize < 37)
			return false;
		buf[0]  = c_HexDigits[(Fields.TimeLow >> 28) & 0xF];
		buf[1]  = c_HexDigits[(Fields.TimeLow >> 24) & 0xF];
		buf[2]  = c_HexDigits[(Fields.TimeLow >> 20) & 0xF];
		buf[3]  = c_HexDigits[(Fields.TimeLow >> 16) & 0xF];
		buf[4]  = c_HexDigits[(Fields.TimeLow >> 12) & 0xF];
		buf[5]  = c_HexDigits[(Fields.TimeLow >> 8) & 0xF];
		buf[6]  = c_HexDigits[(Fields.TimeLow >> 4) & 0xF];
		buf[7]  = c_HexDigits[Fields.TimeLow & 0xF];
		buf[8]  = '-';
		buf[9]  = c_HexDigits[(Fields.TimeMid >> 12) & 0xF];
		buf[10] = c_HexDigits[(Fields.TimeMid >> 8) & 0xF];
		buf[11] = c_HexDigits[(Fields.TimeMid >> 4) & 0xF];
		buf[12] = c_HexDigits[Fields.TimeMid & 0xF];
		buf[13] = '-';
		buf[14] = c_HexDigits[(Fields.TimeHighAndVersion >> 12) & 0xF];
		buf[15] = c_HexDigits[(Fields.TimeHighAndVersion >> 8) & 0xF];
		buf[16] = c_HexDigits[(Fields.TimeHighAndVersion >> 4) & 0xF];
		buf[17] = c_HexDigits[Fields.TimeHighAndVersion & 0xF];
		buf[18] = '-';
		buf[19] = c_HexDigits[(Fields.ClockSeqAndReserved >> 4) & 0xF];
		buf[20] = c_HexDigits[Fields.ClockSeqAndReserved & 0xF];
		buf[21] = c_HexDigits[(Fields.ClockSeqLow >> 4) & 0xF];
		buf[22] = c_HexDigits[Fields.ClockSeqLow & 0xF];
		buf[23] = '-';
		buf[24] = c_HexDigits[(Fields.Node[0] >> 4) & 0xF];
		buf[25] = c_HexDigits[Fields.Node[0] & 0xF];
		buf[26] = c_HexDigits[(Fields.Node[1] >> 4) & 0xF];
		buf[27] = c_HexDigits[Fields.Node[1] & 0xF];
		buf[28] = c_HexDigits[(Fields.Node[2] >> 4) & 0xF];
		buf[29] = c_HexDigits[Fields.Node[2] & 0xF];
		buf[30] = c_HexDigits[(Fields.Node[3] >> 4) & 0xF];
		buf[31] = c_HexDigits[Fields.Node[3] & 0xF];
		buf[32] = c_HexDigits[(Fields.Node[4] >> 4) & 0xF];
		buf[33] = c_HexDigits[Fields.Node[4] & 0xF];
		buf[34] = c_HexDigits[(Fields.Node[5] >> 4) & 0xF];
		buf[35] = c_HexDigits[Fields.Node[5] & 0xF];
		buf[36] = '\0';
		return true;
	}

	constexpr bool operator==(const UUID& other) const noexcept
	{
		return Ints.Low == other.Ints.Low && Ints.High == other.Ints.High;
	}

	constexpr bool operator!=(const UUID& other) const noexcept
	{
		return !(*this == other);
	}
};

UUID GenUUID();
UUID GenUniqueUUID(auto&& fn)
{
	UUID uuid = GenUUID();
	while (fn(uuid))
		uuid = GenUUID();
	return uuid;
}

template <>
struct std::hash<UUID>
{
	constexpr uint64_t operator()(const UUID& uuid) const noexcept
	{
		return std::rotl(uuid.Ints.Low, 3) ^ std::rotr(uuid.Ints.High, 3);
	}
};

template <>
struct std::formatter<UUID>
{
	bool altMode = false;

	template <class ParseContext>
	constexpr ParseContext::iterator parse(ParseContext& ctx)
	{
		auto it = ctx.begin();
		if (it == ctx.end())
			return it;

		if (*it == '#')
		{
			altMode = true;
			++it;
		}
		if (*it != '}')
			throw std::format_error("Invalid format args for UUID.");

		return it;
	}

	template <class FmtContext>
	FmtContext::iterator format(const UUID& uuid, FmtContext& ctx) const
	{
		auto it = ctx.out();
		if (altMode)
			*it++ = '{';
		char buf[37];
		memset(buf, 0, 37);
		uuid.ToString(buf, 37);
		for (size_t i = 0; buf[i] && i < 37; ++i)
			*it++ = buf[i];
		if (altMode)
			*it++ = '}';
		return it;
	}
};

// template <>
// struct std::formatter<UUID&>
//{
//	bool altMode = false;
//
//	template <class ParseContext>
//	constexpr ParseContext::iterator parse(ParseContext& ctx)
//	{
//		auto it = ctx.begin();
//		if (it == ctx.end())
//			return it;
//
//		if (*it == '#')
//		{
//			altMode = true;
//			++it;
//		}
//		if (*it != '}')
//			throw std::format_error("Invalid format args for UUID.");
//
//		return it;
//	}
//
//	template <class FmtContext>
//	FmtContext::iterator format(const UUID& uuid, FmtContext& ctx) const
//	{
//		auto it = ctx.out();
//		if (altMode)
//			*it++ = '{';
//		char buf[37];
//		memset(buf, 0, 37);
//		uuid.ToString(buf, 37);
//		for (size_t i = 0; buf[i] && i < 37; ++i)
//			*it++ = buf[i];
//		if (altMode)
//			*it++ = '}';
//		return it;
//	}
// };