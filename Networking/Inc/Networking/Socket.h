#pragma once

#include "Endpoint.h"

namespace Networking
{
	enum class ESocketError : uint32_t
	{
		Unknown = 0,
		KernelError,
		NoAccess,
		AFNotSupported,
		LowMemory,
		InsufficientPermissions,
		ProtocolNotSupported,
		TypeNotSupported,
		Interrupted,
		InvalidArgument,
		AddressNotAvailable,
		ConnectionRefused,
		NetworkUnreachable,
		HostUnreachable,
		ListenUnsupported,
		AlreadyConnected,
		NetworkDown,
		HostDown,
		ClosedUnexpectedly
	};

	std::string_view SocketErrorToString(ESocketError error);

	enum class ESocketType
	{
		UDP,
		TCP
	};

	class Socket
	{
	public:
		struct SocketSelect
		{
			Socket* Sock             = nullptr;
			bool    CheckRead        = false;
			bool    CheckWrite       = false;
			bool    CheckExceptional = false;
			bool    ReadAvailable    = false;
			bool    WriteAvailable   = false;
			bool    Exceptional      = false;
		};

	public:
		using ErrorCallbackFn = void (*)(Socket* socket, void* userdata, ESocketError error);

		static size_t Select(SocketSelect* selects, size_t count, uint64_t timeout);

	public:
		Socket();
		Socket(ESocketType type, uint32_t writeTimeout = 2000, uint32_t readTimeout = 2000);
		Socket(const Socket&) = delete;
		Socket(Socket&& move) noexcept;
		~Socket();

		Socket& operator=(const Socket&) = delete;
		Socket& operator=(Socket&& move) noexcept;

		size_t Read(void* buf, size_t length);
		size_t ReadFrom(void* buf, size_t length, Endpoint& endpoint);
		size_t Write(std::string_view buf);
		size_t Write(const void* buf, size_t length);
		size_t WriteTo(std::string_view buf, Endpoint endpoint);
		size_t WriteTo(const void* buf, size_t length, Endpoint endpoint);

		bool Bind(Endpoint endpoint);
		bool Connect(Endpoint endpoint);
		void Close();

		void CloseW();
		void CloseR();
		void CloseRW();

		bool   Listen(uint32_t backlog);
		Socket Accept();

		void SetType(ESocketType type);
		void SetWriteTimeout(uint32_t timeout);
		void SetReadTimeout(uint32_t timeout);
		void SetNonBlocking();
		void SetErrorCallback(ErrorCallbackFn callback, void* userdata);

		auto  GetType() const { return m_Type; }
		auto& GetLocalEndpoint() const { return m_LocalEndpoint; }
		auto& GetRemoteEndpoint() const { return m_RemoteEndpoint; }
		auto  GetWriteTimeout() const { return m_WriteTimeout; }
		auto  GetReadTimeout() const { return m_ReadTimeout; }
		auto  GetSocket() const { return m_Socket; }
		bool  IsBound() const { return m_Socket != ~0ULL; }
		bool  IsConnected() const { return m_RemoteEndpoint.IsValid(); }
		auto  GetErrorCallback() const { return m_ErrorCallback; }
		auto  GetUserdata() const { return m_Userdata; }

	private:
		void ReportError(uint32_t errorCode);
		void ReportError(ESocketError error);

		void UpdateTimeouts(uint32_t read, uint32_t write);

	private:
		ESocketType m_Type;
		Endpoint    m_LocalEndpoint;
		Endpoint    m_RemoteEndpoint;

		uint32_t m_WriteTimeout;
		uint32_t m_ReadTimeout;

		uintptr_t m_Socket;

		ErrorCallbackFn m_ErrorCallback;
		void*           m_Userdata;
	};
} // namespace Networking