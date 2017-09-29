
#include <bits/stdc++.h>

#include "util.h"

using namespace std;

string
chars2hex(const unsigned char *s, size_t len) {
    if (s) {
        stringstream ss;
        for (int i = 0; i < len; i++) {
            char buffer[4];
            sprintf(buffer, "%02x", s[i]);
            ss << buffer;
        }
        return ss.str();
    }
    return "*NULL*";
}

void
put_quoted(ostream &out, const unsigned char *data, size_t len, bool breaks, string prefix, string quote) {
    out << prefix << quote;
    for (size_t i = 0; i < len; i++) {
        int c = data[i];
        switch(c) {
        case '\0':
            out << "\\0";
            break;
        case '\a':
            out << "\\a";
            break;
        case '\b':
            out << "\\b";
            break;
        case '\t':
            out << "\\t";
            break;
        case '\n':
            out << "\\n";
            if (breaks && (len - i > 1))
                out << quote << endl << prefix << quote;
            break;
        case '\v':
            out << "\\v";
            break;
        case '\f':
            out << "\\f";
            break;
        case '\r':
            out << "\\r";
            break;
        case '\\':
            out << "\\\\";
            break;
        default:
            if (isprint(c)) {
                out.put(c);
            }
            else {
                char hex[10];
                sprintf(hex, "\\x%02x", c);
                out << hex;
            }
        }
    }
    out << quote;
}

void
put_quoted(ostream &out, const string &str, bool breaks, string prefix, string quote) {
    put_quoted(out, (const unsigned char*)str.c_str(), str.length(), breaks, prefix, quote);
}

static inline void
ltrim(string &s) {
    s.erase(s.begin(),
            find_if(s.begin(), s.end(),
                         [](int ch) { return !isspace(ch); } ) );
}

static inline void
rtrim(string &s) {
    s.erase(find_if(s.rbegin(), s.rend(),
                         [](int ch) { return !isspace(ch); } ).base(), s.end());
}

// trim from both ends (in place)
static inline void trim(string &s) {
    ltrim(s);
    rtrim(s);
}

void
split_and_append(vector<string> &v, const string &s, char delim) {
    stringstream ss;
    ss.str(s);
    string item;
    while (getline(ss, item, delim)) {
        trim(item);
        if (item.length())
            v.push_back(item);
    }
}
