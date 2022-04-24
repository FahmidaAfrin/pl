/*************************************************************************
    > File Name: simple_little_endian.h
  > Author: Wei Sun
  > Mail:sunweiflyus@gmail.com 
  > Created Time: Fri 23 Jun 2017 10:14:13 PM CDT
  > Comments: 
 ************************************************************************/

#ifndef __SIMPLE_LITTLE_ENDIAN_H__
#define __SIMPLE_LITTLE_ENDIAN_H__


#define __constant_cpu_to_be32(x) ((__force __be32)___constant_swab32((x)))

#endif
