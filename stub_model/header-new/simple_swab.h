/*************************************************************************
    > File Name: simple_swab.h
  > Author: Wei Sun
  > Mail:sunweiflyus@gmail.com 
  > Created Time: Fri 23 Jun 2017 10:13:10 PM CDT
  > Comments: 
 ************************************************************************/

#ifndef __SIMPLE_SWAB_H__
#define __SIMPLE_SWAB_H__

#define ___constant_swab32(x)//((__u32)(				\
	(((__u32)(x) & (__u32)0x000000ffUL) << 24) |		\
	(((__u32)(x) & (__u32)0x0000ff00UL) <<  8) |		\
	(((__u32)(x) & (__u32)0x00ff0000UL) >>  8) |		\
	(((__u32)(x) & (__u32)0xff000000UL) >> 24)))

#endif
