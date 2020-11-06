/** 
 * @file helper.h
 * @author Yuchen Gu <llgyc@pku.edu.cn>
 * @brief Library with useful functions.
 */
 
#ifndef __TINYTCP_HELPER_H__
#define __TINYTCP_HELPER_H__

namespace tinytcp {
namespace helper {
    
/**
 * @brief Reverse the endian of a number. 
 *
 * @param num The number to be reversed.
 * @return The reversed number
 */
uint16_t endian_reverse(uint16_t num);
uint32_t endian_reverse(uint32_t num);

}
}

#endif
