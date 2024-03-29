#pragma once

#include <cstdint>

template <class T>
struct DataView
{
public:
	constexpr DataView()
		: m_First(nullptr),
		  m_Last(nullptr) {}
	constexpr DataView(T* first, size_t length)
		: m_First(first),
		  m_Last(first + length) {}
	constexpr DataView(T* first, T* last)
		: m_First(first),
		  m_Last(last) {}
	constexpr DataView(const DataView& copy)
		: m_First(copy.m_First),
		  m_Last(copy.m_Last) {}

	constexpr DataView& operator=(const DataView& copy)
	{
		m_First = copy.m_First;
		m_Last  = copy.m_Last;
		return *this;
	}

	constexpr size_t size() const { return m_Last - m_First; }
	constexpr bool   empty() const { return size() == 0; }

	constexpr T*       begin() { return m_First; }
	constexpr T*       end() { return m_Last; }
	constexpr const T* begin() const { return m_First; }
	constexpr const T* end() const { return m_Last; }
	constexpr const T* cbegin() const { return m_First; }
	constexpr const T* cend() const { return m_Last; }

	constexpr T&       operator[](size_t index) { return m_First[index]; }
	constexpr const T& operator[](size_t index) const { return m_First[index]; }

private:
	T* m_First;
	T* m_Last;
};

using ByteView = DataView<const uint8_t>;