#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <sddl.h>
#include <atlsecurity.h>

#include <cstdlib>
#include <stdexcept>
#include <system_error>
#include <vector>
#include <format>
#include <iostream>
#include <memory>
