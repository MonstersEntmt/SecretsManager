#include "Utils/UUID.h"
#include "Utils/Time.h"

#include <random>

static std::mt19937_64 s_UUIDRNG(std::random_device {}());

UUID GenUUID()
{
	UUID uuid;
	uuid.Ints.Low                   = Time::CurUnixTime();
	uuid.Ints.High                  = s_UUIDRNG();
	uuid.Fields.ClockSeqAndReserved = uuid.Fields.ClockSeqAndReserved & 0x3F | 0x80;
	uuid.Fields.TimeHighAndVersion  = uuid.Fields.TimeHighAndVersion & 0x0FFF | 0x4000;
	return uuid;
}