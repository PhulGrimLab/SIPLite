#include "SipUtils.h"
#include <cassert>
#include <iostream>

int main()
{
    {
        std::string s = "  hello \t\n";
        assert(trim(s) == "hello");
        std::cout << "trim test passed\n";
    }

    {
        std::string v = "via\r\n"
                        "more";
        assert(sanitizeHeaderValue(v) == "viamore");
        std::cout << "sanitizeHeaderValue test passed\n";
    }

    {
        std::string hdr = "To: <sip:1001@server>;tag=abc";
        assert(extractUriFromHeader(hdr) == "sip:1001@server");
        std::cout << "extractUriFromHeader test passed\n";
    }

    {
        std::string uri = "sip:1002@server-ip";
        assert(extractUserFromUri(uri) == "1002");
        std::cout << "extractUserFromUri test passed\n";
    }

    std::cout << "All utils tests passed\n";
    return 0;
}
