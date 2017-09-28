
#include <bits/stdc++.h>

std::string chars2hex(const unsigned char *s, size_t len);
void put_quoted(std::ostream &, const unsigned char *, size_t,
                bool breaks = false, std::string prefix = "", std::string quote = "\"");
void put_quoted(std::ostream &, const std::string &,
                bool breaks = false, std::string prefix = "", std::string quote = "\"");

void split_and_append(std::vector<std::string> &v, const std::string &s, char delim=',');
