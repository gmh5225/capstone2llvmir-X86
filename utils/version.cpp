/**
 * @file src/utils/version.cpp
 * @brief RetDec version implementation.
 * @copyright (c) 2021 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/version.h"

// DIY
#define RETDEC_GIT_COMMIT_HASH "1234"
#define RETDEC_BUILD_DATE "20220519"
#define RETDEC_GIT_VERSION_TAG "tag1234"

namespace retdec {
namespace utils {
namespace version {

std::string getCommitHash()
{
	return RETDEC_GIT_COMMIT_HASH;
}

std::string getShortCommitHash(unsigned length)
{
	return getCommitHash().substr(0, length);
}

std::string getBuildDate()
{
	return RETDEC_BUILD_DATE;
}

std::string getVersionTag()
{
	return RETDEC_GIT_VERSION_TAG;
}

std::string getVersionStringLong()
{
	return "123";
}

std::string getVersionStringShort()
{
	return "123";
}

} // namespace version
} // namespace utils
} // namespace retdec
