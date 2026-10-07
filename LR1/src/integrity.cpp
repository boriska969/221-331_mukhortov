#include "integrity.hpp"

#include <windows.h>

#include <cstring>

#include "crypto_utils.hpp"

namespace lr1 {
namespace {

const char kReferenceTextHash[] =
    "LR1TEXTHASH:"
    "0000000000000000000000000000000000000000000000000000000000000000"
    ":END";

constexpr std::size_t kMarkerLength = 12;
constexpr std::size_t kHashHexLength = 64;

static_assert(sizeof(kReferenceTextHash) == kMarkerLength + kHashHexLength + 4 + 1,
              "эталонный хеш должен занимать ровно 64 символа после маркера");

}

bool isDebuggerAttached() {
    return IsDebuggerPresent() != FALSE;
}

bool computeTextSegmentHash(std::string& hexOut, std::string& error) {
    hexOut.clear();
    const auto base = reinterpret_cast<const unsigned char*>(GetModuleHandleW(nullptr));
    if (base == nullptr) {
        error = "GetModuleHandleW вернул NULL";
        return false;
    }
    const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        error = "неверная сигнатура DOS-заголовка";
        return false;
    }
    const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        error = "неверная сигнатура PE-заголовка";
        return false;
    }

    const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD index = 0; index < ntHeaders->FileHeader.NumberOfSections; ++index, ++section) {
        if (std::memcmp(section->Name, ".text\0\0\0", IMAGE_SIZEOF_SHORT_NAME) == 0) {
            const unsigned char* textStart = base + section->VirtualAddress;
            const std::size_t textSize = section->Misc.VirtualSize;
            hexOut = sha256Hex(textStart, textSize);
            return !hexOut.empty();
        }
    }
    error = "секция .text не найдена";
    return false;
}

bool isTextSegmentIntact(std::string& error) {
    std::string actual;
    if (!computeTextSegmentHash(actual, error)) {
        return false;
    }
    const std::string expected(kReferenceTextHash + kMarkerLength, kHashHexLength);
    if (actual != expected) {
        error = "контрольная сумма сегмента .text не совпадает с эталоном";
        return false;
    }
    return true;
}

}
