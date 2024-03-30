#include "Testing/Tests.h"

#include <Concurrency/Mutex.h>
#include <Networking/Socket.h>

#include <iostream>
#include <sstream>
#include <thread>
#include <vector>

static void ErrorCallback(Networking::Socket* socket, void* userdata, Networking::ESocketError error)
{
	std::ostringstream str;
	str << "SOCKET ERROR " << Networking::SocketErrorToString(error) << '\n';
	std::cout << str.str();
}

Networking::Socket                            s_Server(Networking::ESocketType::TCP);
std::vector<Networking::Socket::SocketSelect> s_Selects;
std::vector<Networking::Socket>               s_Clients;
std::vector<Networking::Socket>               s_NewClients;
Concurrency::Mutex                            s_ClientsMtx;
std::atomic_size_t                            s_ClientCount = 0;

static void ClientAcceptor()
{
	while (s_Server.IsBound())
	{
		auto client = s_Server.Accept();
		if (!client.IsBound())
			continue;

		if (s_Clients.size() > 32)
		{
			client.Close();
			continue;
		}

		{
			char endpoint[128];
			client.GetRemoteEndpoint().ToString(endpoint, 128);
			std::ostringstream str;
			str << "Client connected from " << endpoint << '\n';
			std::cout << str.str();
		}
		Concurrency::Lock(s_ClientsMtx);
		s_NewClients.emplace_back(std::move(client));
		Concurrency::Unlock(s_ClientsMtx);
		++s_ClientCount;
		s_ClientCount.notify_one();
	}
}

int main([[maybe_unused]] int argc, [[maybe_unused]] char** argv)
{
	s_Server.SetErrorCallback(&ErrorCallback, nullptr);

	if (!s_Server.Bind({ Networking::IPv4Address(127, 0, 0, 1), 12287 }))
		return 1;

	if (!s_Server.Listen(32))
		return 1;

	{
		char endpoint[128];
		s_Server.GetLocalEndpoint().ToString(endpoint, 128);
		std::ostringstream str;
		str << "Server hosting on endpoint " << endpoint << '\n';
		std::cout << str.str();
	}

	std::thread acceptorThread(&ClientAcceptor);

	while (s_Server.IsBound())
	{
		s_ClientCount.wait(0);
		Concurrency::Lock(s_ClientsMtx);
		if (!s_NewClients.empty())
		{
			for (size_t i = 0; i < s_NewClients.size(); ++i)
			{
				auto client = std::move(s_NewClients[i]);
				client.SetNonBlocking();
				s_Clients.emplace_back(std::move(client));
				s_Selects.resize(s_Clients.size());
			}
			s_NewClients.clear();
		}
		Concurrency::Unlock(s_ClientsMtx);

		for (size_t i = 0; i < s_Selects.size(); ++i)
		{
			auto& sock              = s_Clients[i];
			auto& select            = s_Selects[i];
			select.Sock             = &sock;
			select.CheckRead        = true;
			select.CheckWrite       = false;
			select.CheckExceptional = false;
		}

		Networking::Socket::Select(s_Selects.data(), s_Selects.size(), ~0ULL);

		for (size_t i = 0; i < s_Selects.size(); ++i)
		{
			auto& select = s_Selects[i];
			if (select.ReadAvailable)
			{
				auto& sock = *select.Sock;

				std::ostringstream str;
				{
					char endpoint[128];
					sock.GetRemoteEndpoint().ToString(endpoint, 128);
					str << endpoint << ": ";
				}

				char   buf[16];
				size_t readLength = sock.Read(buf, 16);
				str << std::string_view { buf, readLength } << '\n';
				std::cout << str.str();
			}
		}
	}

	acceptorThread.join();

	// Testing::RunTests();
}