#include "Networking/Socket.h"

#include <Build.h>

#if BUILD_IS_SYSTEM_WINDOWS
	#include <WinSock2.h>
	#include <WS2tcpip.h>
	#include <afunix.h>
	#undef GetAddrInfo
	#undef FreeAddrInfo
	#undef GetNameInfo
#else
	#include <fcntl.h>
	#include <netdb.h>
	#include <netinet/in.h>
	#include <sys/socket.h>
	#include <sys/types.h>
	#include <unistd.h>
#endif

namespace Networking
{
	using ssize_t = std::make_signed_t<size_t>;

	namespace Platform
	{
#if BUILD_IS_SYSTEM_WINDOWS
		static struct WSAState
		{
			WSAState()
			{
				Initialized = !WSAStartup(MAKEWORD(2, 2), &Data);
			}

			~WSAState()
			{
				WSACleanup();
				Initialized = false;
			}

			WSAData Data;
			bool    Initialized;
		} s_WSAState;
#endif

		static uint32_t GetPID()
		{
#if BUILD_IS_SYSTEM_WINDOWS
			return (uint32_t) GetCurrentProcessId();
#else
			return (uint32_t) getpid();
#endif
		}

		static uint32_t LastError()
		{
#if BUILD_IS_SYSTEM_WINDOWS
			return WSAGetLastError();
#else
			return errno;
#endif
		}

		enum class EShutdownMethod
		{
			Receive,
			Send,
			Both
		};

		static int GetNativeShutdownMethod(EShutdownMethod method)
		{
			switch (method)
			{
#if BUILD_IS_SYSTEM_WINDOWS
			case EShutdownMethod::Receive: return SD_RECEIVE;
			case EShutdownMethod::Send: return SD_SEND;
			default: return SD_BOTH;
#else
			case EShutdownMethod::Receive: return SHUT_RD;
			case EShutdownMethod::Send: return SHUT_WR;
			default: return SHUT_RDWR;
#endif
			}
		}

		static uintptr_t CreateSocket(int af, int type, int protocol)
		{
			return (uintptr_t)::socket(af, type, protocol);
		}

		static uintptr_t CreateSocketEx(int af, int type, int protocol, [[maybe_unused]] void* lpProtocolInfo, [[maybe_unused]] uint32_t g, [[maybe_unused]] uint32_t dwFlags)
		{
#if BUILD_IS_SYSTEM_WINDOWS
			return (uintptr_t)::WSASocketW(af, type, protocol, (LPWSAPROTOCOL_INFOW) lpProtocolInfo, (GROUP) g, (DWORD) dwFlags);
#else
			return (uintptr_t)::socket(af, type, protocol);
#endif
		}

		static int CloseSocket(uintptr_t socket)
		{
#if BUILD_IS_SYSTEM_WINDOWS
			return ::closesocket((SOCKET) socket);
#else
			return ::close((int) socket);
#endif
		}

		static int Shutdown(uintptr_t socket, EShutdownMethod how)
		{
#if BUILD_IS_SYSTEM_WINDOWS
			return ::shutdown((SOCKET) socket, GetNativeShutdownMethod(how));
#else
			return ::shutdown((int) socket, GetNativeShutdownMethod(how));
#endif
		}

		static int Bind(uintptr_t socket, const sockaddr_storage* addr, size_t addrSize)
		{
#if BUILD_IS_SYSTEM_WINDOWS
			return ::bind((SOCKET) socket, (const sockaddr*) addr, (int) addrSize);
#else
			return ::bind((int) socket, (const sockaddr*) addr, (socklen_t) addrSize);
#endif
		}

		static int Connect(uintptr_t socket, const sockaddr_storage* addr, size_t addrSize)
		{
#if BUILD_IS_SYSTEM_WINDOWS
			return ::connect((SOCKET) socket, (const sockaddr*) addr, (int) addrSize);
#else
			return ::connect((int) socket, (const sockaddr*) addr, (int) addrSize);
#endif
		}

		static int Listen(uintptr_t socket, uint32_t backlog)
		{
#if BUILD_IS_SYSTEM_WINDOWS
			return ::listen((SOCKET) socket, (int) backlog);
#else
			return ::listen((int) socket, (int) backlog);
#endif
		}

		static uintptr_t Accept(uintptr_t socket, sockaddr_storage* addr, size_t* addrSize)
		{
#if BUILD_IS_SYSTEM_WINDOWS
			int  addrSizeS = (int) *addrSize;
			auto r         = ::accept((SOCKET) socket, (sockaddr*) addr, &addrSizeS);
			*addrSize      = (size_t) addrSizeS;
			return (uintptr_t) r;
#else
			socklen_t addrSizeS = (socklen_t) *addrSize;
			auto      r         = ::accept((int) socket, (sockaddr*) addr, &addrSizeS);
			*addrSize           = (size_t) addrSizeS;
			return (uintptr_t) r;
#endif
		}

		static int GetSockName(uintptr_t socket, sockaddr_storage* addr, size_t* addrSize)
		{
#if BUILD_IS_SYSTEM_WINDOWS
			int  addrSizeS = (int) *addrSize;
			auto r         = ::getsockname((SOCKET) socket, (sockaddr*) addr, &addrSizeS);
			*addrSize      = (size_t) addrSizeS;
			return r;
#else
			socklen_t addrSizeS = (socklen_t) *addrSize;
			auto      r         = ::getsockname((int) socket, (sockaddr*) addr, &addrSizeS);
			*addrSize           = (size_t) addrSizeS;
			return r;
#endif
		}

		static int SetSockOpt(uintptr_t socket, int level, int optname, const void* optval, size_t optlen)
		{
#if BUILD_IS_SYSTEM_WINDOWS
			return ::setsockopt((SOCKET) socket, level, optname, (const char*) optval, (int) optlen);
#else
			return ::setsockopt((int) socket, level, optname, optval, (socklen_t) optlen);
#endif
		}

		static int SetNonBlocking(uintptr_t socket, bool nonBlocking)
		{
#if BUILD_IS_SYSTEM_WINDOWS
			u_long mode = nonBlocking;
			return ::ioctlsocket((SOCKET) socket, FIONBIO, &mode);
#else
			int mode = (::fcntl((int) socket, F_GETFL, 0) & ~O_NONBLOCK);
			if (nonBlocking)
				mode |= O_NONBLOCK;
			return ::fcntl((int) socket, F_SETFL, mode);
#endif
		}

		static int Select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, timeval* timeout)
		{
#if BUILD_IS_SYSTEM_WINDOWS
			return ::select(nfds, readfds, writefds, exceptfds, (const timeval*) timeout);
#else
			return ::select(nfds, readfds, writefds, exceptfds, timeout);
#endif
		}

		static void ZeroFD(fd_set* set)
		{
			FD_ZERO(set);
		}

		static void SetFD(fd_set* set, uintptr_t socket)
		{
#if BUILD_IS_SYSTEM_WINDOWS
			FD_SET((SOCKET) socket, set);
#else
			FD_SET((int) socket, set);
#endif
		}

		static int IsSetFD(fd_set* set, uintptr_t socket)
		{
#if BUILD_IS_SYSTEM_WINDOWS
			return FD_ISSET((SOCKET) socket, set);
#else
			return FD_ISSET((int) socket, set);
#endif
		}

		static ssize_t Receive(uintptr_t socket, void* buf, size_t len, int flags)
		{
#if BUILD_IS_SYSTEM_WINDOWS
			return (ssize_t)::recv((SOCKET) socket, (char*) buf, (int) std::min<size_t>(len, std::numeric_limits<int>::max()), flags);
#else
			return (ssize_t)::recv((int) socket, buf, len, flags);
#endif
		}

		static ssize_t ReceiveFrom(uintptr_t socket, void* buf, size_t len, int flags, sockaddr_storage* addr, size_t* addrSize)
		{
#if BUILD_IS_SYSTEM_WINDOWS
			int  addrSizeS = (int) *addrSize;
			auto r         = ::recvfrom((SOCKET) socket, (char*) buf, (int) std::min<size_t>(len, std::numeric_limits<int>::max()), flags, (sockaddr*) addr, &addrSizeS);
			*addrSize      = (size_t) addrSizeS;
			return (ssize_t) r;
#else
			socklen_t addrSizeS = (socklen_t) *addrSize;
			auto      r         = ::recvfrom((int) socket, buf, len, flags, (sockaddr*) addr, &addrSizeS);
			*addrSize           = (size_t) addrSizeS;
			return (ssize_t) r;
#endif
		}

		static ssize_t Send(uintptr_t socket, const void* buf, size_t len, int flags)
		{
#if BUILD_IS_SYSTEM_WINDOWS
			return (ssize_t)::send((SOCKET) socket, (const char*) buf, (int) std::min<size_t>(len, std::numeric_limits<int>::max()), flags);
#else
			return (ssize_t)::send((int) socket, buf, len, flags);
#endif
		}

		static ssize_t SendTo(uintptr_t socket, const void* buf, size_t len, int flags, const sockaddr_storage* addr, size_t addrSize)
		{
#if BUILD_IS_SYSTEM_WINDOWS
			return (ssize_t)::sendto((SOCKET) socket, (const char*) buf, (int) std::min<size_t>(len, std::numeric_limits<int>::max()), flags, (const sockaddr*) addr, (int) addrSize);
#else
			return (ssize_t)::sendto((int) socket, buf, len, flags, (const sockaddr*) addr, (socklen_t) addrSize);
#endif
		}

		static int GetAddrInfo(const char* node, const char* service, const addrinfo* hints, addrinfo** results)
		{
			return ::getaddrinfo(node, service, hints, results);
		}

		static void FreeAddrInfo(addrinfo* addrinfo)
		{
			return ::freeaddrinfo(addrinfo);
		}

		static int GetNameInfo(const sockaddr_storage* addr, size_t addrSize, char* node, size_t nodeSize, char* service, size_t serviceSize, int flags)
		{
#if BUILD_IS_SYSTEM_WINDOWS
			return ::getnameinfo((const sockaddr*) addr, (socklen_t) addrSize, node, (DWORD) nodeSize, service, (DWORD) serviceSize, flags);
#else
			return ::getnameinfo((const sockaddr*) addr, (socklen_t) addrSize, node, (socklen_t) nodeSize, service, (socklen_t) serviceSize, flags);
#endif
		}

		static bool IsErrorCloseBased(uint32_t errorCode)
		{
			switch (errorCode)
			{
#if BUILD_IS_SYSTEM_WINDOWS
			case WSANOTINITIALISED:
			case WSAENETDOWN:
			case WSAENOTCONN:
			case WSAENETRESET:
			case WSAENOTSOCK:
			case WSAESHUTDOWN:
			case WSAECONNABORTED:
			case WSAETIMEDOUT:
			case WSAECONNRESET:
#else
			case ENOTCONN:
			case ENOTSOCK:
			case ETIMEDOUT:
			case ECONNRESET:
#endif
				return true;
			default: return false;
			}
		}

		static bool IsErrorCodeAnError(uint32_t errorCode)
		{
			switch (errorCode)
			{
#if BUILD_IS_SYSTEM_WINDOWS
			case WSAEWOULDBLOCK:
#else
			case EAGAIN:
#endif
				return false;
			default:
				return true;
			}
		}

		static ESocketError GetSocketError(uint32_t errorCode)
		{
			switch (errorCode)
			{
#if BUILD_IS_SYSTEM_WINDOWS
			case WSAEFAULT:
			case WSAEMFILE:
			case WSAEINVALIDPROVIDER:
			case WSAEINVALIDPROCTABLE:
			case WSANOTINITIALISED: return ESocketError::KernelError;
			case WSAEACCES: return ESocketError::NoAccess;
			case WSAEAFNOSUPPORT: return ESocketError::AFNotSupported;
			case WSAENOBUFS: return ESocketError::LowMemory;
			case WSAEPROTONOSUPPORT: return ESocketError::ProtocolNotSupported;
			case WSAESOCKTNOSUPPORT:
			case WSAEPROTOTYPE: return ESocketError::TypeNotSupported;
			case WSAEINTR: return ESocketError::Interrupted;
			case WSAEBADF:
			case WSAEINVAL: return ESocketError::InvalidArgument;
			case WSAEADDRINUSE:
			case WSAEADDRNOTAVAIL: return ESocketError::AddressNotAvailable;
			case WSAECONNREFUSED: return ESocketError::ConnectionRefused;
			case WSAENETUNREACH: return ESocketError::NetworkUnreachable;
			case WSAEHOSTUNREACH: return ESocketError::HostUnreachable;
			case WSAEOPNOTSUPP:
			case WSAEDESTADDRREQ: return ESocketError::ListenUnsupported;
			case WSAEISCONN: return ESocketError::AlreadyConnected;
			case WSAENETDOWN: return ESocketError::NetworkDown;
			case WSAEHOSTDOWN: return ESocketError::HostDown;
#else
			case EIO:
			case EFAULT:
			case EMFILE:
			case ENFILE: return ESocketError::KernelError;
			case EACCES: return ESocketError::NoAccess;
			case EAFNOSUPPORT: return ESocketError::AFNotSupported;
			case ENOSPC:
			case ENOMEM:
			case ENOBUFS: return ESocketError::LowMemory;
			case EPERM: return ESocketError::InsufficientPermissions;
			case EPROTONOSUPPORT: return ESocketError::ProtocolNotSupported;
			case EPROTOTYPE: return ESocketError::TypeNotSupported;
			case EINTR: return ESocketError::Interrupted;
			case EBADF:
			case EINVAL: return ESocketError::InvalidArgument;
			case EADDRINUSE:
			case EADDRNOTAVAIL: return ESocketError::AddressNotAvailable;
			case ECONNREFUSED: return ESocketError::ConnectionRefused;
			case ENETUNREACH: return ESocketError::NetworkUnreachable;
			case EHOSTUNREACH: return ESocketError::HostUnreachable;
			case EOPNOTSUPP:
			case EDESTADDRREQ: return ESocketError::ListenUnsupported;
			case EISCONN: return ESocketError::AlreadyConnected;
			case ENETDOWN: return ESocketError::NetworkDown;
			case EHOSTDOWN: return ESocketError::HostDown;
#endif
			default: return ESocketError::Unknown;
			}
		}

		static int GetNativeAddressFamily(EEndpointType type)
		{
			switch (type)
			{
			case EEndpointType::IPv4: return AF_INET;
			case EEndpointType::IPv6: return AF_INET6;
			case EEndpointType::Path: return AF_UNIX;
			default: return AF_INET;
			}
		}

		static int GetNativeSocketType(ESocketType type)
		{
			switch (type)
			{
			case ESocketType::UDP: return SOCK_DGRAM;
			case ESocketType::TCP: return SOCK_STREAM;
			default: return SOCK_DGRAM;
			}
		}

		static int GetNativeSocketProtocol(EEndpointType endpointType, ESocketType type)
		{
			switch (endpointType)
			{
			case EEndpointType::IPv4:
			case EEndpointType::IPv6:
				switch (type)
				{
				case ESocketType::UDP: return IPPROTO_UDP;
				case ESocketType::TCP: return IPPROTO_TCP;
				default: return IPPROTO_UDP;
				}
			case EEndpointType::Path: return 0;
			default: return 0;
			}
		}

		static void ToSockAddr(const Endpoint& endpoint, sockaddr_storage* addr, size_t* addrSize)
		{
			memset(addr, 0, sizeof(sockaddr_storage));
			switch (endpoint.GetType())
			{
			case EEndpointType::IPv4:
			{
				const AddressEndpoint& addrEndpoint = endpoint.GetAddress();

				*addrSize             = sizeof(sockaddr_in);
				sockaddr_in* ipv4     = (sockaddr_in*) addr;
				ipv4->sin_family      = AF_INET;
				ipv4->sin_port        = htons(addrEndpoint.Port);
				ipv4->sin_addr.s_addr = addrEndpoint.Addr.IPv4.Value;
#if BUILD_IS_SYSTEM_MACOSX
				addr->ss_len = (uint8_t) *addrSize;
#endif
				break;
			}
			case EEndpointType::IPv6:
			{
				const AddressEndpoint& addrEndpoint = endpoint.GetAddress();

				*addrSize          = sizeof(sockaddr_in6);
				sockaddr_in6* ipv6 = (sockaddr_in6*) addr;
				ipv6->sin6_family  = AF_INET6;
				ipv6->sin6_port    = htons(addrEndpoint.Port);
				for (size_t i = 0; i < 8; ++i)
				{
					ipv6->sin6_addr.s6_addr[i * 2]     = addrEndpoint.Addr.IPv6.Segments[i] & 0xFF;
					ipv6->sin6_addr.s6_addr[i * 2 + 1] = (addrEndpoint.Addr.IPv6.Segments[i] >> 8) & 0xFF;
				}
#if BUILD_IS_SYSTEM_MACOSX
				addr->ss_len = (uint8_t) *addrSize;
#endif
				break;
			}
			case EEndpointType::Path:
			{
				const PathEndpoint& pathEndpoint = endpoint.GetPath();

				*addrSize       = sizeof(sockaddr_un);
				sockaddr_un* un = (sockaddr_un*) addr;
				un->sun_family  = AF_UNIX;
				memcpy(un->sun_path, pathEndpoint.Path.c_str(), std::min<size_t>(pathEndpoint.Path.size(), UNIX_PATH_MAX - 1));
				un->sun_path[UNIX_PATH_MAX - 1] = '\0';
#if BUILD_IS_SYSTEM_MACOSX
				addr->ss_len = (uint8_t) *addrSize;
#endif
				break;
			}
			}
		}

		static void ToEndpoint(Endpoint& endpoint, const sockaddr_storage* addr)
		{
			switch (addr->ss_family)
			{
			case AF_INET:
			{
				AddressEndpoint    addrEndpoint;
				const sockaddr_in* ipv4 = (const sockaddr_in*) addr;
				addrEndpoint.Addr       = IPv4Address(ipv4->sin_addr.s_addr);
				addrEndpoint.Port       = ntohs(ipv4->sin_port);
				endpoint                = addrEndpoint;
				break;
			}
			case AF_INET6:
			{
				AddressEndpoint     addrEndpoint;
				const sockaddr_in6* ipv6 = (const sockaddr_in6*) addr;
				addrEndpoint.Port        = ntohs(ipv6->sin6_port);
				for (size_t i = 0; i < 8; ++i)
					addrEndpoint.Addr.IPv6.Segments[i] = ipv6->sin6_addr.s6_addr[i * 2 + 1] << 8 | ipv6->sin6_addr.s6_addr[i * 2];
				endpoint = addrEndpoint;
				break;
			}
			case AF_UNIX:
			{
				PathEndpoint       pathEndpoint;
				const sockaddr_un* un = (const sockaddr_un*) addr;
				pathEndpoint.Path.resize(strlen(un->sun_path));
				memcpy(pathEndpoint.Path.data(), un->sun_path, pathEndpoint.Path.size());
				endpoint = std::move(pathEndpoint);
				break;
			}
			default:
				endpoint = Endpoint {};
				break;
			}
		}
	} // namespace Platform

	std::string_view SocketErrorToString(ESocketError error)
	{
		switch (error)
		{
		case ESocketError::Unknown: return "Unknown error";
		case ESocketError::KernelError: return "Kernel error";
		case ESocketError::NoAccess: return "No access";
		case ESocketError::AFNotSupported: return "Address family is not supported";
		case ESocketError::LowMemory: return "Low memory, please make sure to free enough memory";
		case ESocketError::InsufficientPermissions: return "Insufficient permissions";
		case ESocketError::ProtocolNotSupported: return "Protocol is not supported";
		case ESocketError::TypeNotSupported: return "Socket type is not supported";
		case ESocketError::Interrupted: return "Socket was interrupted";
		case ESocketError::InvalidArgument: return "Invalid argument passed to socket";
		case ESocketError::AddressNotAvailable: return "Address is not available";
		case ESocketError::ConnectionRefused: return "Connection was refused";
		case ESocketError::NetworkUnreachable: return "Network is unreachable";
		case ESocketError::HostUnreachable: return "Host is unreachable";
		case ESocketError::ListenUnsupported: return "Listen is unsupported";
		case ESocketError::AlreadyConnected: return "Socket is already connected";
		case ESocketError::NetworkDown: return "Network is down";
		case ESocketError::HostDown: return "Host is down";
		case ESocketError::ClosedUnexpectedly: return "Closed unexpectedly";
		default: return "Unknown error";
		}
	}

	size_t Socket::Select(SocketSelect* selects, size_t count, uint64_t timeout)
	{
		if (count > FD_SETSIZE)
		{
			for (size_t i = 0; i < count; ++i)
			{
				auto& select          = selects[i];
				select.ReadAvailable  = false;
				select.WriteAvailable = false;
				select.Exceptional    = false;
			}
			return 0;
		}

		int    readfdCount   = 0;
		int    writefdCount  = 0;
		int    exceptfdCount = 0;
		fd_set readfds;
		fd_set writefds;
		fd_set exceptfds;
		Platform::ZeroFD(&readfds);
		Platform::ZeroFD(&writefds);
		Platform::ZeroFD(&exceptfds);
		for (size_t i = 0; i < count; ++i)
		{
			auto& select = selects[i];
			auto  socket = select.Sock->m_Socket;
			if (select.CheckRead)
			{
				Platform::SetFD(&readfds, socket);
				++readfdCount;
			}
			if (select.CheckWrite)
			{
				Platform::SetFD(&writefds, socket);
				++writefdCount;
			}
			if (select.CheckExceptional)
			{
				Platform::SetFD(&exceptfds, socket);
				++exceptfdCount;
			}
		}
		int     maxfdCount = std::max({ readfdCount, writefdCount, exceptfdCount });
		timeval timeo;
		timeo.tv_usec = (long) (timeout % 1'000'000);
		timeo.tv_sec  = (long) (timeout / 1'000'000);
		if (Platform::Select(maxfdCount + 1, &readfds, &writefds, &exceptfds, timeout != ~0ULL ? &timeo : nullptr) < 0)
		{
			if (Platform::IsErrorCodeAnError(Platform::LastError()))
			{
				for (size_t i = 0; i < count; ++i)
				{
					auto& select          = selects[i];
					select.ReadAvailable  = false;
					select.WriteAvailable = false;
					select.Exceptional    = false;
				}
				return 0;
			}
		}
		size_t ready = 0;
		for (size_t i = 0; i < count; ++i)
		{
			auto& select          = selects[i];
			auto  socket          = select.Sock->m_Socket;
			select.ReadAvailable  = select.CheckRead ? Platform::IsSetFD(&readfds, socket) : false;
			select.WriteAvailable = select.CheckWrite ? Platform::IsSetFD(&writefds, socket) : false;
			select.Exceptional    = select.CheckExceptional ? Platform::IsSetFD(&exceptfds, socket) : false;
			if (select.ReadAvailable || select.WriteAvailable || select.Exceptional)
				++ready;
		}
		return ready;
	}

	Socket::Socket()
		: m_Type(ESocketType::UDP),
		  m_WriteTimeout(2000),
		  m_ReadTimeout(2000),
		  m_Socket(~0ULL),
		  m_ErrorCallback(nullptr),
		  m_Userdata(nullptr) {}

	Socket::Socket(ESocketType type, uint32_t writeTimeout, uint32_t readTimeout)
		: m_Type(type),
		  m_WriteTimeout(writeTimeout),
		  m_ReadTimeout(readTimeout),
		  m_Socket(~0ULL),
		  m_ErrorCallback(nullptr),
		  m_Userdata(nullptr) {}

	Socket::Socket(Socket&& move) noexcept
		: m_Type(move.m_Type),
		  m_LocalEndpoint(move.m_LocalEndpoint),
		  m_RemoteEndpoint(move.m_RemoteEndpoint),
		  m_WriteTimeout(move.m_WriteTimeout),
		  m_ReadTimeout(move.m_ReadTimeout),
		  m_Socket(move.m_Socket),
		  m_ErrorCallback(move.m_ErrorCallback),
		  m_Userdata(move.m_Userdata)
	{
		move.m_LocalEndpoint  = Endpoint {};
		move.m_RemoteEndpoint = Endpoint {};
		move.m_Socket         = ~0ULL;
		move.m_ErrorCallback  = nullptr;
		move.m_Userdata       = nullptr;
	}

	Socket::~Socket()
	{
		if (IsBound())
			Close();
	}

	Socket& Socket::operator=(Socket&& move) noexcept
	{
		m_Type                = move.m_Type;
		m_LocalEndpoint       = move.m_LocalEndpoint;
		m_RemoteEndpoint      = move.m_RemoteEndpoint;
		m_WriteTimeout        = move.m_WriteTimeout;
		m_ReadTimeout         = move.m_ReadTimeout;
		m_Socket              = move.m_Socket;
		m_ErrorCallback       = move.m_ErrorCallback;
		m_Userdata            = move.m_Userdata;
		move.m_LocalEndpoint  = Endpoint {};
		move.m_RemoteEndpoint = Endpoint {};
		move.m_Socket         = ~0ULL;
		move.m_ErrorCallback  = nullptr;
		move.m_Userdata       = nullptr;
		return *this;
	}

	size_t Socket::Read(void* buf, size_t length)
	{
		if (!IsBound())
			return 0;

		uint8_t* data   = (uint8_t*) buf;
		size_t   offset = 0;
		while (length != 0)
		{
			auto r = Platform::Receive(m_Socket, data, length, 0);
			if (r < 0)
			{
				auto errorCode = Platform::LastError();
				if (Platform::IsErrorCloseBased(errorCode))
				{
					ReportError(ESocketError::ClosedUnexpectedly);
					Close();
				}
				else if (Platform::IsErrorCodeAnError(errorCode))
				{
					ReportError(errorCode);
				}
			}

			if (r <= 0)
				break;

			offset += r;
			length -= r;
			data   += r;
		}
		return offset;
	}

	size_t Socket::ReadFrom(void* buf, size_t length, Endpoint& endpoint)
	{
		if (!IsBound())
			return 0;

		sockaddr_storage addr {};
		size_t           addrSize = sizeof(addr);

		ssize_t r = 0;
		if (IsConnected())
		{
			r = Platform::Receive(m_Socket, buf, length, 0);
			Platform::ToSockAddr(m_RemoteEndpoint, &addr, &addrSize);
		}
		else
		{
			r = Platform::ReceiveFrom(m_Socket, buf, length, 0, &addr, &addrSize);
		}

		if (r <= 0)
		{
			auto errorCode = Platform::LastError();
			if (Platform::IsErrorCloseBased(errorCode))
			{
				ReportError(ESocketError::ClosedUnexpectedly);
				Close();
			}
			else if (Platform::IsErrorCodeAnError(errorCode))
			{
				ReportError(errorCode);
			}
			return 0;
		}
		Platform::ToEndpoint(endpoint, &addr);
		return (size_t) r;
	}

	size_t Socket::Write(std::string_view buf)
	{
		return Write(buf.data(), buf.size());
	}

	size_t Socket::Write(const void* buf, size_t length)
	{
		if (!IsBound())
			return 0;

		const uint8_t* data   = (const uint8_t*) buf;
		size_t         offset = 0;
		while (length != 0)
		{
			auto r = Platform::Send(m_Socket, buf, length, 0);
			if (r < 0)
			{
				auto errorCode = Platform::LastError();
				if (Platform::IsErrorCloseBased(errorCode))
				{
					ReportError(ESocketError::ClosedUnexpectedly);
					Close();
				}
				else if (Platform::IsErrorCodeAnError(errorCode))
				{
					ReportError(errorCode);
				}
			}

			if (r <= 0)
				break;

			offset += r;
			length -= r;
			data   += r;
		}
		return offset;
	}

	size_t Socket::WriteTo(std::string_view buf, Endpoint endpoint)
	{
		return WriteTo(buf.data(), buf.size(), endpoint);
	}

	size_t Socket::WriteTo(const void* buf, size_t length, Endpoint endpoint)
	{
		if (!IsBound())
			return 0;

		if (IsConnected())
		{
			if (endpoint == m_RemoteEndpoint)
				return Write(buf, length);
			ReportError(ESocketError::AlreadyConnected);
			return 0;
		}

		sockaddr_storage addr {};
		size_t           addrSize = sizeof(addr);
		Platform::ToSockAddr(endpoint, &addr, &addrSize);

		const uint8_t* data   = (const uint8_t*) buf;
		size_t         offset = 0;
		while (length != 0)
		{
			auto r = Platform::SendTo(m_Socket, data, length, 0, &addr, addrSize);
			if (r < 0)
			{
				auto errorCode = Platform::LastError();
				if (Platform::IsErrorCloseBased(errorCode))
				{
					ReportError(ESocketError::ClosedUnexpectedly);
					Close();
				}
				else if (Platform::IsErrorCodeAnError(errorCode))
				{
					ReportError(errorCode);
				}
			}

			if (r <= 0)
				break;

			offset += r;
			length -= r;
			data   += r;
		}
		return offset;
	}

	bool Socket::Bind(Endpoint endpoint)
	{
		if (IsBound())
			return false;

#if BUILD_IS_SYSTEM_WINDOWS
		if (!Platform::s_WSAState.Initialized)
			return false;
#endif

		m_Socket = Platform::CreateSocket(
			Platform::GetNativeAddressFamily(endpoint.GetType()),
			Platform::GetNativeSocketType(m_Type),
			Platform::GetNativeSocketProtocol(endpoint.GetType(), m_Type));
		if (!IsBound())
		{
			ReportError(Platform::LastError());
			return false;
		}

		sockaddr_storage addr {};
		size_t           addrSize = sizeof(addr);
		Platform::ToSockAddr(endpoint, &addr, &addrSize);
		if (Platform::Bind(m_Socket, &addr, addrSize) < 0)
		{
			ReportError(Platform::LastError());
			Close();
			return false;
		}
		m_LocalEndpoint  = Endpoint {};
		m_RemoteEndpoint = Endpoint {};

		if (Platform::SetSockOpt(m_Socket, SOL_SOCKET, SO_SNDTIMEO, &m_WriteTimeout, sizeof(m_WriteTimeout)) < 0 ||
			Platform::SetSockOpt(m_Socket, SOL_SOCKET, SO_RCVTIMEO, &m_ReadTimeout, sizeof(m_ReadTimeout)) < 0)
			ReportError(Platform::LastError());

		if (Platform::GetSockName(m_Socket, &addr, &addrSize) < 0)
			ReportError(Platform::LastError());
		else
			Platform::ToEndpoint(m_LocalEndpoint, &addr);
		return true;
	}

	bool Socket::Connect(Endpoint endpoint)
	{
		if (IsBound())
			return false;

#if BUILD_IS_SYSTEM_WINDOWS
		if (!Platform::s_WSAState.Initialized)
			return false;
#endif

		m_Socket = Platform::CreateSocket(
			Platform::GetNativeAddressFamily(endpoint.GetType()),
			Platform::GetNativeSocketType(m_Type),
			Platform::GetNativeSocketProtocol(endpoint.GetType(), m_Type));
		if (!IsBound())
		{
			ReportError(Platform::LastError());
			return false;
		}

		sockaddr_storage addr {};
		size_t           addrSize = sizeof(addr);
		if (endpoint.GetType() == EEndpointType::Path)
		{
			constexpr const char c_HexDigits[] = "0123456789ABCDEF";

			uint32_t pid  = Platform::GetPID();
			uint64_t sock = (uint64_t) m_Socket;
			char     buf[31];
			buf[0]  = c_HexDigits[(pid >> 28) & 0xF];
			buf[1]  = c_HexDigits[(pid >> 24) & 0xF];
			buf[2]  = c_HexDigits[(pid >> 20) & 0xF];
			buf[3]  = c_HexDigits[(pid >> 16) & 0xF];
			buf[4]  = c_HexDigits[(pid >> 12) & 0xF];
			buf[5]  = c_HexDigits[(pid >> 8) & 0xF];
			buf[6]  = c_HexDigits[(pid >> 4) & 0xF];
			buf[7]  = c_HexDigits[pid & 0xF];
			buf[8]  = '-';
			buf[9]  = c_HexDigits[(sock >> 60) & 0xF];
			buf[10] = c_HexDigits[(sock >> 56) & 0xF];
			buf[11] = c_HexDigits[(sock >> 52) & 0xF];
			buf[12] = c_HexDigits[(sock >> 48) & 0xF];
			buf[13] = c_HexDigits[(sock >> 44) & 0xF];
			buf[14] = c_HexDigits[(sock >> 40) & 0xF];
			buf[15] = c_HexDigits[(sock >> 36) & 0xF];
			buf[16] = c_HexDigits[(sock >> 32) & 0xF];
			buf[17] = c_HexDigits[(sock >> 28) & 0xF];
			buf[18] = c_HexDigits[(sock >> 24) & 0xF];
			buf[19] = c_HexDigits[(sock >> 20) & 0xF];
			buf[20] = c_HexDigits[(sock >> 16) & 0xF];
			buf[21] = c_HexDigits[(sock >> 12) & 0xF];
			buf[22] = c_HexDigits[(sock >> 8) & 0xF];
			buf[23] = c_HexDigits[(sock >> 4) & 0xF];
			buf[24] = c_HexDigits[sock & 0xF];
			buf[25] = '.';
			buf[26] = 's';
			buf[27] = 'o';
			buf[28] = 'c';
			buf[29] = 'k';
			buf[30] = '\0';
			Platform::ToSockAddr({ buf }, &addr, &addrSize);
			if (Platform::Bind(m_Socket, &addr, addrSize) < 0)
			{
				ReportError(Platform::LastError());
				Close();
				return false;
			}
			addrSize = sizeof(addr);
		}

		Platform::ToSockAddr(endpoint, &addr, &addrSize);
		if (Platform::Connect(m_Socket, &addr, addrSize) < 0)
		{
			ReportError(Platform::LastError());
			Close();
			return false;
		}
		m_RemoteEndpoint = std::move(endpoint);

		if (Platform::SetSockOpt(m_Socket, SOL_SOCKET, SO_SNDTIMEO, &m_WriteTimeout, sizeof(m_WriteTimeout)) < 0 ||
			Platform::SetSockOpt(m_Socket, SOL_SOCKET, SO_RCVTIMEO, &m_ReadTimeout, sizeof(m_ReadTimeout)) < 0)
			ReportError(Platform::LastError());

		if (Platform::GetSockName(m_Socket, &addr, &addrSize) < 0)
			ReportError(Platform::LastError());
		else
			Platform::ToEndpoint(m_LocalEndpoint, &addr);
		return true;
	}

	void Socket::Close()
	{
		if (!IsBound())
			return;

		if (Platform::CloseSocket(m_Socket) < 0)
			ReportError(Platform::LastError());
		m_Socket         = ~0ULL;
		m_LocalEndpoint  = Endpoint {};
		m_RemoteEndpoint = Endpoint {};
	}

	void Socket::CloseW()
	{
		if (!IsBound())
			return;

		if (Platform::Shutdown(m_Socket, Platform::EShutdownMethod::Send) < 0)
			ReportError(Platform::LastError());
	}

	void Socket::CloseR()
	{
		if (!IsBound())
			return;

		if (Platform::Shutdown(m_Socket, Platform::EShutdownMethod::Receive) < 0)
			ReportError(Platform::LastError());
	}

	void Socket::CloseRW()
	{
		if (!IsBound())
			return;

		if (Platform::Shutdown(m_Socket, Platform::EShutdownMethod::Both) < 0)
			ReportError(Platform::LastError());
	}

	bool Socket::Listen(uint32_t backlog)
	{
		if (!IsBound() && m_Type != ESocketType::TCP)
			return false;

		if (Platform::Listen(m_Socket, backlog) < 0)
		{
			ReportError(Platform::LastError());
			return false;
		}
		return true;
	}

	Socket Socket::Accept()
	{
		Socket socket = Socket(m_Type);
		if (!IsBound() && m_Type != ESocketType::TCP)
			return socket;

		socket.SetErrorCallback(m_ErrorCallback, m_Userdata);
		socket.SetWriteTimeout(m_WriteTimeout);
		socket.SetReadTimeout(m_ReadTimeout);

		sockaddr_storage addr {};
		size_t           addrSize = sizeof(addr);
		socket.m_Socket           = Platform::Accept(m_Socket, &addr, &addrSize);
		if (!socket.IsBound())
		{
			ReportError(Platform::LastError());
			return socket;
		}
		Platform::ToEndpoint(socket.m_RemoteEndpoint, &addr);

		if (Platform::SetSockOpt(socket.m_Socket, SOL_SOCKET, SO_SNDTIMEO, &socket.m_WriteTimeout, sizeof(socket.m_WriteTimeout)) < 0 ||
			Platform::SetSockOpt(socket.m_Socket, SOL_SOCKET, SO_RCVTIMEO, &socket.m_ReadTimeout, sizeof(socket.m_ReadTimeout)) < 0)
			socket.ReportError(Platform::LastError());

		if (Platform::GetSockName(socket.m_Socket, &addr, &addrSize) < 0)
			socket.ReportError(Platform::LastError());
		else
			Platform::ToEndpoint(socket.m_LocalEndpoint, &addr);
		return socket;
	}

	void Socket::SetType(ESocketType type)
	{
		if (!IsBound())
			m_Type = type;
		else
			ReportError(ESocketError::AlreadyConnected);
	}

	void Socket::SetWriteTimeout(uint32_t timeout)
	{
		UpdateTimeouts(m_ReadTimeout, timeout);
	}

	void Socket::SetReadTimeout(uint32_t timeout)
	{
		UpdateTimeouts(timeout, m_WriteTimeout);
	}

	void Socket::SetNonBlocking()
	{
		UpdateTimeouts(0, 0);
	}

	void Socket::SetErrorCallback(ErrorCallbackFn callback, void* userdata)
	{
		m_ErrorCallback = callback;
		m_Userdata      = userdata;
	}

	void Socket::ReportError(uint32_t errorCode)
	{
		ReportError(Platform::GetSocketError(errorCode));
	}

	void Socket::ReportError(ESocketError error)
	{
		if (m_ErrorCallback)
			m_ErrorCallback(this, m_Userdata, error);
	}

	void Socket::UpdateTimeouts(uint32_t read, uint32_t write)
	{
		bool shouleBeNonBlocking = read == 0 || write == 0;
		if (shouleBeNonBlocking)
		{
			if (IsBound())
			{
				if (m_WriteTimeout == 0)
					return;
				if (Platform::SetNonBlocking(m_Socket, true) < 0)
				{
					ReportError(Platform::LastError());
					return;
				}
			}
			m_WriteTimeout = 0;
			m_ReadTimeout  = 0;
		}
		else
		{
			if (IsBound())
			{
				if ((m_WriteTimeout == 0 &&
					 Platform::SetNonBlocking(m_Socket, false) < 0) ||
					Platform::SetSockOpt(m_Socket, SOL_SOCKET, SO_RCVTIMEO, &read, sizeof(read)) < 0 ||
					Platform::SetSockOpt(m_Socket, SOL_SOCKET, SO_SNDTIMEO, &write, sizeof(write)) < 0)
				{
					ReportError(Platform::LastError());
					return;
				}
			}
			m_ReadTimeout  = read;
			m_WriteTimeout = write;
		}
	}

	Endpoint Endpoint::ResolveFromHost(std::string_view node, std::string_view service, EEndpointType type)
	{
		std::string nodeStr { node };
		std::string serviceStr { service };

		addrinfo hints {};
		switch (type)
		{
		case EEndpointType::IPv4: hints.ai_family = AF_INET; break;
		case EEndpointType::IPv6: hints.ai_family = AF_INET6; break;
		default: hints.ai_family = AF_UNSPEC; break;
		}
		hints.ai_flags = AI_PASSIVE;

		addrinfo* results;
		if (Platform::GetAddrInfo(nodeStr.c_str(), serviceStr.c_str(), &hints, &results) < 0)
			return {};

		if (!results)
			return {};

		Endpoint endpoint;
		Platform::ToEndpoint(endpoint, (const sockaddr_storage*) results->ai_addr);
		Platform::FreeAddrInfo(results);
		return endpoint;
	}

	std::string Endpoint::ToHost(const Endpoint& endpoint)
	{
		std::string      nodeName(NI_MAXHOST, '\0');
		std::string      serviceName(NI_MAXHOST, '\0');
		sockaddr_storage addr {};
		size_t           addrSize = sizeof(addr);
		Platform::ToSockAddr(endpoint, &addr, &addrSize);
		if (Platform::GetNameInfo(&addr, addrSize, nodeName.data(), nodeName.size(), serviceName.data(), serviceName.size(), 0) < 0)
			return {};
		return serviceName + "://" + nodeName;
	}
} // namespace Networking