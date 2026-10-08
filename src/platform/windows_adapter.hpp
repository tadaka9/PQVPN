#pragma once

#ifdef _WIN32

#include "adapter.hpp"
#include "windows_own_tunnel.hpp"

namespace pqvpn::platform {
// Windows deliberately exposes only the PQVPN-owned layer-3 driver backend.
}

#endif
