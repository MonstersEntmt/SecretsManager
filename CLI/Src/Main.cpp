#include <Networking/Socket.h>

#include <iostream>
#include <sstream>

static void ErrorCallback(Networking::Socket* socket, void* userdata, Networking::ESocketError error)
{
	std::ostringstream str;
	str << "SOCKET ERROR " << Networking::SocketErrorToString(error) << '\n';
	std::cout << str.str();
}

int main()
{
	Networking::Socket client(Networking::ESocketType::TCP);
	client.SetErrorCallback(&ErrorCallback, nullptr);

	if (!client.Connect({ Networking::IPv4Address(127, 0, 0, 1), 12287 }))
		return 1;

	std::string input;
	while (client.IsBound())
	{
		std::getline(std::cin, input);

		client.Write(input);
	}
}