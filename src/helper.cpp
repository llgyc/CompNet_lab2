#include <stdint.h>
#include <algorithm>

#include "../inc/helper.h"

namespace tinytcp {
namespace helper {
    

uint16_t endian_reverse(uint16_t num) {
    uint8_t *ptr = (uint8_t *)&num;
    std::swap(ptr[0], ptr[1]);
    return num;
}
uint32_t endian_reverse(uint32_t num) {
    uint8_t *ptr = (uint8_t *)&num;
    std::swap(ptr[0], ptr[3]);
    std::swap(ptr[1], ptr[2]);
    return num;
}



}
}
