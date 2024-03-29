#include "Tests.h"
#include "TestCrypto.h"

#include <Testing/Testing.h>

namespace Testing
{
	void RunTests()
	{
		Begin();
		TestCrypto();
		End();
	}
}