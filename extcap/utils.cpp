#include <algorithm>
#include <iomanip>
#include <stdexcept>
#include "utils.h"
#include <sstream>
#include <iostream>

using std::string;


string to_string(const data_t& data) {
    std::stringstream out;
    out << std::hex;
    for (uint8_t d : data) {
        try {
            out << std::setfill('0') << std::hex << std::setw(2) << static_cast<int>(d);
        } catch (...){}
    }
    return out.str();
}


data_t from_string(std::string hex)
{
        data_t data;
        for (auto i = 0u; i < hex.length(); i += 2) {
            try {
                data.push_back(static_cast<data_t::value_type>(std::stol(hex.substr(i, 2), nullptr, 16)));
            } catch (...){}
        }

        return data;
}
