#include "Utils/Time.h"

#include <time.h>

namespace Time
{
	uint64_t CurUnixTime()
	{
		return (uint64_t) time(nullptr); // TODO(MarcasRealAccount): Please use something better than this, mostly on non unix oses
	}
} // namespace Time