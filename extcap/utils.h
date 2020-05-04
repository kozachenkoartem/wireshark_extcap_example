#ifndef UTILS_H
#define UTILS_H

#include <vector>
#include <string>

#define DATA_BUFFER_SIZE 0xff

typedef std::vector<char> data_t;
std::string to_string(const data_t& data);
data_t from_string(std::string hex);

#endif /* UTILS_H */
