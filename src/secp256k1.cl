#ifdef OPENCL

#pragma OPENCL EXTENSION cl_khr_int64_base_atomics : enable

#define uint32_t uint
#define uint64_t ulong
#define int64_t long
#define int32_t int
#define bool uint

#define UINT32_MAX       0xffffffff

#define get_local_id( x ) ( (uint)get_local_id( x ) )
#define get_global_id( x ) ( (uint)get_global_id( x ) )
#define get_global_offset( x ) ( (uint)get_global_offset( x ) )

#define ROTL32( x, n ) rotate( (uint)( x ), (uint)( n ) )
#define ROTR32( x, n ) rotate( (uint)( x ), (uint)( 32 - ( n ) ) )
#define SHR( x, n ) ( ( x ) >> ( n ) )
#define SWAP4( x ) as_uint( as_uchar4( x ).wzyx )

#define SWAP32(a)	(as_uint(as_uchar4(a).wzyx))
#define SWAP64(x)	as_ulong(as_uchar8(x).s32107654)  /// hmm...

#define sha256_S0(x) (ROTL32(x, 25) ^ ROTL32(x, 14) ^  SHR(x, 3))
#define sha256_S1(x) (ROTL32(x, 15) ^ ROTL32(x, 13) ^  SHR(x, 10))

#define sha256_S2(x) (ROTL32(x, 30) ^ ROTL32(x, 19) ^ ROTL32(x, 10))
#define sha256_S3(x) (ROTL32(x, 26) ^ ROTL32(x, 21) ^ ROTL32(x, 7))

#define sha256_P( a, b, c, d, e, f, g, h, x, K ) \
{\
	temp1 = h + sha256_S3( e ) + sha256_F1( e, f, g ) + ( K + x );\
	d += temp1;\
	h = temp1 + sha256_S2( a ) + sha256_F0( a, b, c );\
}

#define sha256_F0( y, x, z ) bitselect( z, y, z ^ x )
#define sha256_F1( x, y, z ) bitselect( z, y, x )

#define sha256_R0 (W0 = sha256_S1(W14) + W9 + sha256_S0(W1) + W0)
#define sha256_R1 (W1 = sha256_S1(W15) + W10 + sha256_S0(W2) + W1)
#define sha256_R2 (W2 = sha256_S1(W0) + W11 + sha256_S0(W3) + W2)
#define sha256_R3 (W3 = sha256_S1(W1) + W12 + sha256_S0(W4) + W3)
#define sha256_R4 (W4 = sha256_S1(W2) + W13 + sha256_S0(W5) + W4)
#define sha256_R5 (W5 = sha256_S1(W3) + W14 + sha256_S0(W6) + W5)
#define sha256_R6 (W6 = sha256_S1(W4) + W15 + sha256_S0(W7) + W6)
#define sha256_R7 (W7 = sha256_S1(W5) + W0 + sha256_S0(W8) + W7)
#define sha256_R8 (W8 = sha256_S1(W6) + W1 + sha256_S0(W9) + W8)
#define sha256_R9 (W9 = sha256_S1(W7) + W2 + sha256_S0(W10) + W9)
#define sha256_R10 (W10 = sha256_S1(W8) + W3 + sha256_S0(W11) + W10)
#define sha256_R11 (W11 = sha256_S1(W9) + W4 + sha256_S0(W12) + W11)
#define sha256_R12 (W12 = sha256_S1(W10) + W5 + sha256_S0(W13) + W12)
#define sha256_R13 (W13 = sha256_S1(W11) + W6 + sha256_S0(W14) + W13)
#define sha256_R14 (W14 = sha256_S1(W12) + W7 + sha256_S0(W15) + W14)
#define sha256_R15 (W15 = sha256_S1(W13) + W8 + sha256_S0(W0) + W15)

#define sha256_RD14 (sha256_S1(W12) + W7 + sha256_S0(W15) + W14)
#define sha256_RD15 (sha256_S1(W13) + W8 + sha256_S0(W0) + W15)

// generic sha transform
static inline uint8 sha256_Transform( uint16 data, uint8 state )
{
	volatile uint temp1;
	volatile uint8 res = state;
	volatile uint W0 = data.s0;
	volatile uint W1 = data.s1;
	volatile uint W2 = data.s2;
	volatile uint W3 = data.s3;
	volatile uint W4 = data.s4;
	volatile uint W5 = data.s5;
	volatile uint W6 = data.s6;
	volatile uint W7 = data.s7;
	volatile uint W8 = data.s8;
	volatile uint W9 = data.s9;
	volatile uint W10 = data.sA;
	volatile uint W11 = data.sB;
	volatile uint W12 = data.sC;
	volatile uint W13 = data.sD;
	volatile uint W14 = data.sE;
	volatile uint W15 = data.sF;

	#define v0  res.s0
	#define v1  res.s1
	#define v2  res.s2
	#define v3  res.s3
	#define v4  res.s4
	#define v5  res.s5
	#define v6  res.s6
	#define v7  res.s7

	sha256_P(v0, v1, v2, v3, v4, v5, v6, v7, W0, 0x428A2F98);
	sha256_P(v7, v0, v1, v2, v3, v4, v5, v6, W1, 0x71374491);
	sha256_P(v6, v7, v0, v1, v2, v3, v4, v5, W2, 0xB5C0FBCF);
	sha256_P(v5, v6, v7, v0, v1, v2, v3, v4, W3, 0xE9B5DBA5);
	sha256_P(v4, v5, v6, v7, v0, v1, v2, v3, W4, 0x3956C25B);
	sha256_P(v3, v4, v5, v6, v7, v0, v1, v2, W5, 0x59F111F1);
	sha256_P(v2, v3, v4, v5, v6, v7, v0, v1, W6, 0x923F82A4);
	sha256_P(v1, v2, v3, v4, v5, v6, v7, v0, W7, 0xAB1C5ED5);
	sha256_P(v0, v1, v2, v3, v4, v5, v6, v7, W8, 0xD807AA98);
	sha256_P(v7, v0, v1, v2, v3, v4, v5, v6, W9, 0x12835B01);
	sha256_P(v6, v7, v0, v1, v2, v3, v4, v5, W10, 0x243185BE);
	sha256_P(v5, v6, v7, v0, v1, v2, v3, v4, W11, 0x550C7DC3);
	sha256_P(v4, v5, v6, v7, v0, v1, v2, v3, W12, 0x72BE5D74);
	sha256_P(v3, v4, v5, v6, v7, v0, v1, v2, W13, 0x80DEB1FE);
	sha256_P(v2, v3, v4, v5, v6, v7, v0, v1, W14, 0x9BDC06A7);
	sha256_P(v1, v2, v3, v4, v5, v6, v7, v0, W15, 0xC19BF174);

	sha256_P(v0, v1, v2, v3, v4, v5, v6, v7, sha256_R0, 0xE49B69C1);
	sha256_P(v7, v0, v1, v2, v3, v4, v5, v6, sha256_R1, 0xEFBE4786);
	sha256_P(v6, v7, v0, v1, v2, v3, v4, v5, sha256_R2, 0x0FC19DC6);
	sha256_P(v5, v6, v7, v0, v1, v2, v3, v4, sha256_R3, 0x240CA1CC);
	sha256_P(v4, v5, v6, v7, v0, v1, v2, v3, sha256_R4, 0x2DE92C6F);
	sha256_P(v3, v4, v5, v6, v7, v0, v1, v2, sha256_R5, 0x4A7484AA);
	sha256_P(v2, v3, v4, v5, v6, v7, v0, v1, sha256_R6, 0x5CB0A9DC);
	sha256_P(v1, v2, v3, v4, v5, v6, v7, v0, sha256_R7, 0x76F988DA);
	sha256_P(v0, v1, v2, v3, v4, v5, v6, v7, sha256_R8, 0x983E5152);
	sha256_P(v7, v0, v1, v2, v3, v4, v5, v6, sha256_R9, 0xA831C66D);
	sha256_P(v6, v7, v0, v1, v2, v3, v4, v5, sha256_R10, 0xB00327C8);
	sha256_P(v5, v6, v7, v0, v1, v2, v3, v4, sha256_R11, 0xBF597FC7);
	sha256_P(v4, v5, v6, v7, v0, v1, v2, v3, sha256_R12, 0xC6E00BF3);
	sha256_P(v3, v4, v5, v6, v7, v0, v1, v2, sha256_R13, 0xD5A79147);
	sha256_P(v2, v3, v4, v5, v6, v7, v0, v1, sha256_R14, 0x06CA6351);
	sha256_P(v1, v2, v3, v4, v5, v6, v7, v0, sha256_R15, 0x14292967);

	sha256_P(v0, v1, v2, v3, v4, v5, v6, v7, sha256_R0, 0x27B70A85);
	sha256_P(v7, v0, v1, v2, v3, v4, v5, v6, sha256_R1, 0x2E1B2138);
	sha256_P(v6, v7, v0, v1, v2, v3, v4, v5, sha256_R2, 0x4D2C6DFC);
	sha256_P(v5, v6, v7, v0, v1, v2, v3, v4, sha256_R3, 0x53380D13);
	sha256_P(v4, v5, v6, v7, v0, v1, v2, v3, sha256_R4, 0x650A7354);
	sha256_P(v3, v4, v5, v6, v7, v0, v1, v2, sha256_R5, 0x766A0ABB);
	sha256_P(v2, v3, v4, v5, v6, v7, v0, v1, sha256_R6, 0x81C2C92E);
	sha256_P(v1, v2, v3, v4, v5, v6, v7, v0, sha256_R7, 0x92722C85);
	sha256_P(v0, v1, v2, v3, v4, v5, v6, v7, sha256_R8, 0xA2BFE8A1);
	sha256_P(v7, v0, v1, v2, v3, v4, v5, v6, sha256_R9, 0xA81A664B);
	sha256_P(v6, v7, v0, v1, v2, v3, v4, v5, sha256_R10, 0xC24B8B70);
	sha256_P(v5, v6, v7, v0, v1, v2, v3, v4, sha256_R11, 0xC76C51A3);
	sha256_P(v4, v5, v6, v7, v0, v1, v2, v3, sha256_R12, 0xD192E819);
	sha256_P(v3, v4, v5, v6, v7, v0, v1, v2, sha256_R13, 0xD6990624);
	sha256_P(v2, v3, v4, v5, v6, v7, v0, v1, sha256_R14, 0xF40E3585);
	sha256_P(v1, v2, v3, v4, v5, v6, v7, v0, sha256_R15, 0x106AA070);

	sha256_P(v0, v1, v2, v3, v4, v5, v6, v7, sha256_R0, 0x19A4C116);
	sha256_P(v7, v0, v1, v2, v3, v4, v5, v6, sha256_R1, 0x1E376C08);
	sha256_P(v6, v7, v0, v1, v2, v3, v4, v5, sha256_R2, 0x2748774C);
	sha256_P(v5, v6, v7, v0, v1, v2, v3, v4, sha256_R3, 0x34B0BCB5);
	sha256_P(v4, v5, v6, v7, v0, v1, v2, v3, sha256_R4, 0x391C0CB3);
	sha256_P(v3, v4, v5, v6, v7, v0, v1, v2, sha256_R5, 0x4ED8AA4A);
	sha256_P(v2, v3, v4, v5, v6, v7, v0, v1, sha256_R6, 0x5B9CCA4F);
	sha256_P(v1, v2, v3, v4, v5, v6, v7, v0, sha256_R7, 0x682E6FF3);
	sha256_P(v0, v1, v2, v3, v4, v5, v6, v7, sha256_R8, 0x748F82EE);
	sha256_P(v7, v0, v1, v2, v3, v4, v5, v6, sha256_R9, 0x78A5636F);
	sha256_P(v6, v7, v0, v1, v2, v3, v4, v5, sha256_R10, 0x84C87814);
	sha256_P(v5, v6, v7, v0, v1, v2, v3, v4, sha256_R11, 0x8CC70208);
	sha256_P(v4, v5, v6, v7, v0, v1, v2, v3, sha256_R12, 0x90BEFFFA);
	sha256_P(v3, v4, v5, v6, v7, v0, v1, v2, sha256_R13, 0xA4506CEB);
	sha256_P(v2, v3, v4, v5, v6, v7, v0, v1, sha256_RD14, 0xBEF9A3F7);
	sha256_P(v1, v2, v3, v4, v5, v6, v7, v0, sha256_RD15, 0xC67178F2);

	#undef v0
	#undef v1
	#undef v2
	#undef v3
	#undef v4
	#undef v5
	#undef v6
	#undef v7

	return ( res + state );
}

static __constant  uint8 H256 =
{
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};



#define MAJ(x, y, z)   bitselect((x), (y), ((z) ^ (x)))

void sha2_step1( uint a, uint b, uint c, uint *d, uint e, uint f, uint g, uint *h, uint in, const uint Kshared )
{
	uint t1,t2;
	uint vxandx = (((f) ^ (g)) & (e)) ^ (g); // xandx(e, f, g);
	uint bsg21 =ROTR32(e, 6) ^ ROTR32(e, 11) ^ ROTR32(e, 25); // bsg2_1(e);
	uint bsg20 =ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22); //bsg2_0(a);
	uint andorv = MAJ(a, b, c);		//((b) & (c)) | (((b) | (c)) & (a)); //andor32(a,b,c);

	t1 = h[0] + bsg21 + vxandx + Kshared + in;
	t2 = bsg20 + andorv;
	d[0] = d[0] + t1;
	h[0] = t1 + t2;
}

void sha2_step2(uint a, uint b, uint c, uint *d, uint e, uint f, uint g, uint *h, uint *in, uint pc ,const uint Kshared )
{
	uint t1,t2;

	int pcidx1 = (pc-2) & 0xF;
	int pcidx2 = (pc-7) & 0xF;
	int pcidx3 = (pc-15) & 0xF;
	uint inx0 = in[pc];
	uint inx1 = in[pcidx1];
	uint inx2 = in[pcidx2];
	uint inx3 = in[pcidx3];


	uint ssg21 = ROTR32(inx1, 17) ^ ROTR32(inx1, 19) ^ ((inx1) >> 10); //ssg2_1(inx1);
	uint ssg20 = ROTR32(inx3, 7) ^ ROTR32(inx3, 18) ^ ((inx3) >> 3); //ssg2_0(inx3);
	uint vxandx = (((f) ^ (g)) & (e)) ^ (g); // xandx(e, f, g);
	uint bsg21 =ROTR32(e, 6) ^ ROTR32(e, 11) ^ ROTR32(e, 25); // bsg2_1(e);
	uint bsg20 =ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22); //bsg2_0(a);
	uint andorv = MAJ(a, b, c);		//((b) & (c)) | (((b) | (c)) & (a)); //andor32(a,b,c);

	in[pc] = ssg21+inx2+ssg20+inx0;

	t1 = h[0] + bsg21 + vxandx + Kshared + in[pc];
	t2 = bsg20 + andorv;
	d[0] =  d[0] + t1;
	h[0] = t1 + t2;
}

static inline void sha256_round(uint* in, uint* r)
{
	uint a = r[0];
	uint b = r[1];
	uint c = r[2];
	uint d = r[3];
	uint e = r[4];
	uint f = r[5];
	uint g = r[6];
	uint h = r[7];

	sha2_step1(a,b,c,&d,e,f,g,&h,in[ 0],0x428A2F98);
	sha2_step1(h,a,b,&c,d,e,f,&g,in[ 1],0x71374491);
	sha2_step1(g,h,a,&b,c,d,e,&f,in[ 2],0xB5C0FBCF);
	sha2_step1(f,g,h,&a,b,c,d,&e,in[ 3],0xE9B5DBA5);
	sha2_step1(e,f,g,&h,a,b,c,&d,in[ 4],0x3956C25B);
	sha2_step1(d,e,f,&g,h,a,b,&c,in[ 5],0x59F111F1);
	sha2_step1(c,d,e,&f,g,h,a,&b,in[ 6],0x923F82A4);
	sha2_step1(b,c,d,&e,f,g,h,&a,in[ 7],0xAB1C5ED5);
	sha2_step1(a,b,c,&d,e,f,g,&h,in[ 8],0xD807AA98);
	sha2_step1(h,a,b,&c,d,e,f,&g,in[ 9],0x12835B01);
	sha2_step1(g,h,a,&b,c,d,e,&f,in[10],0x243185BE);
	sha2_step1(f,g,h,&a,b,c,d,&e,in[11],0x550C7DC3);
	sha2_step1(e,f,g,&h,a,b,c,&d,in[12],0x72BE5D74);
	sha2_step1(d,e,f,&g,h,a,b,&c,in[13],0x80DEB1FE);
	sha2_step1(c,d,e,&f,g,h,a,&b,in[14],0x9BDC06A7);
	sha2_step1(b,c,d,&e,f,g,h,&a,in[15],0xC19BF174);

	sha2_step2(a,b,c,&d,e,f,g,&h,in, 0,0xE49B69C1);
	sha2_step2(h,a,b,&c,d,e,f,&g,in, 1,0xEFBE4786);
	sha2_step2(g,h,a,&b,c,d,e,&f,in, 2,0x0FC19DC6);
	sha2_step2(f,g,h,&a,b,c,d,&e,in, 3,0x240CA1CC);
	sha2_step2(e,f,g,&h,a,b,c,&d,in, 4,0x2DE92C6F);
	sha2_step2(d,e,f,&g,h,a,b,&c,in, 5,0x4A7484AA);
	sha2_step2(c,d,e,&f,g,h,a,&b,in, 6,0x5CB0A9DC);
	sha2_step2(b,c,d,&e,f,g,h,&a,in, 7,0x76F988DA);
	sha2_step2(a,b,c,&d,e,f,g,&h,in, 8,0x983E5152);
	sha2_step2(h,a,b,&c,d,e,f,&g,in, 9,0xA831C66D);
	sha2_step2(g,h,a,&b,c,d,e,&f,in,10,0xB00327C8);
	sha2_step2(f,g,h,&a,b,c,d,&e,in,11,0xBF597FC7);
	sha2_step2(e,f,g,&h,a,b,c,&d,in,12,0xC6E00BF3);
	sha2_step2(d,e,f,&g,h,a,b,&c,in,13,0xD5A79147);
	sha2_step2(c,d,e,&f,g,h,a,&b,in,14,0x06CA6351);
	sha2_step2(b,c,d,&e,f,g,h,&a,in,15,0x14292967);

	sha2_step2(a,b,c,&d,e,f,g,&h,in, 0,0x27B70A85);
	sha2_step2(h,a,b,&c,d,e,f,&g,in, 1,0x2E1B2138);
	sha2_step2(g,h,a,&b,c,d,e,&f,in, 2,0x4D2C6DFC);
	sha2_step2(f,g,h,&a,b,c,d,&e,in, 3,0x53380D13);
	sha2_step2(e,f,g,&h,a,b,c,&d,in, 4,0x650A7354);
	sha2_step2(d,e,f,&g,h,a,b,&c,in, 5,0x766A0ABB);
	sha2_step2(c,d,e,&f,g,h,a,&b,in, 6,0x81C2C92E);
	sha2_step2(b,c,d,&e,f,g,h,&a,in, 7,0x92722C85);
	sha2_step2(a,b,c,&d,e,f,g,&h,in, 8,0xA2BFE8A1);
	sha2_step2(h,a,b,&c,d,e,f,&g,in, 9,0xA81A664B);
	sha2_step2(g,h,a,&b,c,d,e,&f,in,10,0xC24B8B70);
	sha2_step2(f,g,h,&a,b,c,d,&e,in,11,0xC76C51A3);
	sha2_step2(e,f,g,&h,a,b,c,&d,in,12,0xD192E819);
	sha2_step2(d,e,f,&g,h,a,b,&c,in,13,0xD6990624);
	sha2_step2(c,d,e,&f,g,h,a,&b,in,14,0xF40E3585);
	sha2_step2(b,c,d,&e,f,g,h,&a,in,15,0x106AA070);

	sha2_step2(a,b,c,&d,e,f,g,&h,in, 0,0x19A4C116);
	sha2_step2(h,a,b,&c,d,e,f,&g,in, 1,0x1E376C08);
	sha2_step2(g,h,a,&b,c,d,e,&f,in, 2,0x2748774C);
	sha2_step2(f,g,h,&a,b,c,d,&e,in, 3,0x34B0BCB5);
	sha2_step2(e,f,g,&h,a,b,c,&d,in, 4,0x391C0CB3);
	sha2_step2(d,e,f,&g,h,a,b,&c,in, 5,0x4ED8AA4A);
	sha2_step2(c,d,e,&f,g,h,a,&b,in, 6,0x5B9CCA4F);
	sha2_step2(b,c,d,&e,f,g,h,&a,in, 7,0x682E6FF3);
	sha2_step2(a,b,c,&d,e,f,g,&h,in, 8,0x748F82EE);
	sha2_step2(h,a,b,&c,d,e,f,&g,in, 9,0x78A5636F);
	sha2_step2(g,h,a,&b,c,d,e,&f,in,10,0x84C87814);
	sha2_step2(f,g,h,&a,b,c,d,&e,in,11,0x8CC70208);
	sha2_step2(e,f,g,&h,a,b,c,&d,in,12,0x90BEFFFA);
	sha2_step2(d,e,f,&g,h,a,b,&c,in,13,0xA4506CEB);
	sha2_step2(c,d,e,&f,g,h,a,&b,in,14,0xBEF9A3F7);
	sha2_step2(b,c,d,&e,f,g,h,&a,in,15,0xC67178F2);

	r[0] = r[0] + a;
	r[1] = r[1] + b;
	r[2] = r[2] + c;
	r[3] = r[3] + d;
	r[4] = r[4] + e;
	r[5] = r[5] + f;
	r[6] = r[6] + g;
	r[7] = r[7] + h;
}
#else
#include <stdint.h>
#include <stdlib.h>

#define __constant
#define __global

#define ulong uint64_t
#endif

#define SECP256K1_INLINE static inline
#define SECP256K1_RESTRICT __restrict

#define USE_NUM_NONE 1
#define USE_FIELD_INV_BUILTIN 1
#define USE_SCALAR_INV_BUILTIN 1
#define USE_FIELD_10X26 1
#define USE_SCALAR_8X32 1
#define USE_ENDOMORPHISM 0
#define ENABLE_MODULE_ECDH 0
#define ENABLE_MODULE_SCHNORR 0
#define ENABLE_MODULE_RECOVERY 0

// {{{ secp256k1 macros

#define SECP256K1_FLAGS_TYPE_MASK ((1 << 8) - 1)
#define SECP256K1_FLAGS_TYPE_CONTEXT (1 << 0)
#define SECP256K1_FLAGS_TYPE_COMPRESSION (1 << 1)
/** The higher bits contain the actual data. Do not use directly. */
#define SECP256K1_FLAGS_BIT_CONTEXT_VERIFY (1 << 8)
#define SECP256K1_FLAGS_BIT_CONTEXT_SIGN (1 << 9)
#define SECP256K1_FLAGS_BIT_COMPRESSION (1 << 8)

/** Flags to pass to secp256k1_context_create. */
#define SECP256K1_CONTEXT_VERIFY (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY)
#define SECP256K1_CONTEXT_SIGN (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN)
#define SECP256K1_CONTEXT_NONE (SECP256K1_FLAGS_TYPE_CONTEXT)

/** Flag to pass to secp256k1_ec_pubkey_serialize and secp256k1_ec_privkey_export. */
#define SECP256K1_EC_COMPRESSED (SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION)
#define SECP256K1_EC_UNCOMPRESSED (SECP256K1_FLAGS_TYPE_COMPRESSION)

// }}}

// {{{ secp256k1 structs
typedef struct {
    uint32_t x[10];
    uint32_t y[10];
    uint32_t z[10];
    uint32_t dummy[2];
} secp256k1_gej;

typedef struct {
    uint32_t x[10];
    uint32_t y[10];
} secp256k1_ge;

typedef struct {
    uint32_t x[8];
    uint32_t y[8];
} secp256k1_ge_storage;

typedef struct {
    unsigned char data[64];
} secp256k1_pubkey;

typedef struct {
    uint32_t s[8];
    uint32_t buf[16]; /* In big endian */
    size_t bytes;
} secp256k1_sha256_t;

typedef struct {
    secp256k1_sha256_t inner, outer;
} secp256k1_hmac_sha256_t;

typedef struct {
    uint32_t v[8];
    uint32_t k[8];
} secp256k1_rfc6979_hmac_sha256_t;

#define Ch(x,y,z) ((z) ^ ((x) & ((y) ^ (z))))
#define Maj(x,y,z) (((x) & (y)) | ((z) & ((x) | (y))))
#define Sigma0(x) (((x) >> 2 | (x) << 30) ^ ((x) >> 13 | (x) << 19) ^ ((x) >> 22 | (x) << 10))
#define Sigma1(x) (((x) >> 6 | (x) << 26) ^ ((x) >> 11 | (x) << 21) ^ ((x) >> 25 | (x) << 7))
#define sigma0(x) (((x) >> 7 | (x) << 25) ^ ((x) >> 18 | (x) << 14) ^ ((x) >> 3))
#define sigma1(x) (((x) >> 17 | (x) << 15) ^ ((x) >> 19 | (x) << 13) ^ ((x) >> 10))

#define Round(a,b,c,d,e,f,g,h,k,w) { \
    uint32_t t1 = (h) + Sigma1(e) + Ch((e), (f), (g)) + (k) + (w); \
    uint32_t t2 = Sigma0(a) + Maj((a), (b), (c)); \
    (d) += t1; \
    (h) = t1 + t2; \
}

#define BE32(p) ((((p) & 0xFF) << 24) | (((p) & 0xFF00) << 8) | (((p) & 0xFF0000) >> 8) | (((p) & 0xFF000000) >> 24))

#ifdef OPENCL
void memcpy( unsigned char *dst, const unsigned char *src, uint32_t size )
{
	for ( int i = 0; i < size; i++ ) dst[ i ] = src[ i ];
}
#endif

static void secp256k1_sha256_initialize(secp256k1_sha256_t *hash) {
    hash->s[0] = 0x6a09e667ul;
    hash->s[1] = 0xbb67ae85ul;
    hash->s[2] = 0x3c6ef372ul;
    hash->s[3] = 0xa54ff53aul;
    hash->s[4] = 0x510e527ful;
    hash->s[5] = 0x9b05688cul;
    hash->s[6] = 0x1f83d9abul;
    hash->s[7] = 0x5be0cd19ul;
    hash->bytes = 0;
}

/** Perform one SHA-256 transformation, processing 16 big endian 32-bit words. */
static void secp256k1_sha256_transform(uint32_t* s, const uint32_t* chunk) {
    uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
    uint32_t w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15;

    Round(a, b, c, d, e, f, g, h, 0x428a2f98, w0 = BE32(chunk[0]));
    Round(h, a, b, c, d, e, f, g, 0x71374491, w1 = BE32(chunk[1]));
    Round(g, h, a, b, c, d, e, f, 0xb5c0fbcf, w2 = BE32(chunk[2]));
    Round(f, g, h, a, b, c, d, e, 0xe9b5dba5, w3 = BE32(chunk[3]));
    Round(e, f, g, h, a, b, c, d, 0x3956c25b, w4 = BE32(chunk[4]));
    Round(d, e, f, g, h, a, b, c, 0x59f111f1, w5 = BE32(chunk[5]));
    Round(c, d, e, f, g, h, a, b, 0x923f82a4, w6 = BE32(chunk[6]));
    Round(b, c, d, e, f, g, h, a, 0xab1c5ed5, w7 = BE32(chunk[7]));
    Round(a, b, c, d, e, f, g, h, 0xd807aa98, w8 = BE32(chunk[8]));
    Round(h, a, b, c, d, e, f, g, 0x12835b01, w9 = BE32(chunk[9]));
    Round(g, h, a, b, c, d, e, f, 0x243185be, w10 = BE32(chunk[10]));
    Round(f, g, h, a, b, c, d, e, 0x550c7dc3, w11 = BE32(chunk[11]));
    Round(e, f, g, h, a, b, c, d, 0x72be5d74, w12 = BE32(chunk[12]));
    Round(d, e, f, g, h, a, b, c, 0x80deb1fe, w13 = BE32(chunk[13]));
    Round(c, d, e, f, g, h, a, b, 0x9bdc06a7, w14 = BE32(chunk[14]));
    Round(b, c, d, e, f, g, h, a, 0xc19bf174, w15 = BE32(chunk[15]));

    Round(a, b, c, d, e, f, g, h, 0xe49b69c1, w0 += sigma1(w14) + w9 + sigma0(w1));
    Round(h, a, b, c, d, e, f, g, 0xefbe4786, w1 += sigma1(w15) + w10 + sigma0(w2));
    Round(g, h, a, b, c, d, e, f, 0x0fc19dc6, w2 += sigma1(w0) + w11 + sigma0(w3));
    Round(f, g, h, a, b, c, d, e, 0x240ca1cc, w3 += sigma1(w1) + w12 + sigma0(w4));
    Round(e, f, g, h, a, b, c, d, 0x2de92c6f, w4 += sigma1(w2) + w13 + sigma0(w5));
    Round(d, e, f, g, h, a, b, c, 0x4a7484aa, w5 += sigma1(w3) + w14 + sigma0(w6));
    Round(c, d, e, f, g, h, a, b, 0x5cb0a9dc, w6 += sigma1(w4) + w15 + sigma0(w7));
    Round(b, c, d, e, f, g, h, a, 0x76f988da, w7 += sigma1(w5) + w0 + sigma0(w8));
    Round(a, b, c, d, e, f, g, h, 0x983e5152, w8 += sigma1(w6) + w1 + sigma0(w9));
    Round(h, a, b, c, d, e, f, g, 0xa831c66d, w9 += sigma1(w7) + w2 + sigma0(w10));
    Round(g, h, a, b, c, d, e, f, 0xb00327c8, w10 += sigma1(w8) + w3 + sigma0(w11));
    Round(f, g, h, a, b, c, d, e, 0xbf597fc7, w11 += sigma1(w9) + w4 + sigma0(w12));
    Round(e, f, g, h, a, b, c, d, 0xc6e00bf3, w12 += sigma1(w10) + w5 + sigma0(w13));
    Round(d, e, f, g, h, a, b, c, 0xd5a79147, w13 += sigma1(w11) + w6 + sigma0(w14));
    Round(c, d, e, f, g, h, a, b, 0x06ca6351, w14 += sigma1(w12) + w7 + sigma0(w15));
    Round(b, c, d, e, f, g, h, a, 0x14292967, w15 += sigma1(w13) + w8 + sigma0(w0));

    Round(a, b, c, d, e, f, g, h, 0x27b70a85, w0 += sigma1(w14) + w9 + sigma0(w1));
    Round(h, a, b, c, d, e, f, g, 0x2e1b2138, w1 += sigma1(w15) + w10 + sigma0(w2));
    Round(g, h, a, b, c, d, e, f, 0x4d2c6dfc, w2 += sigma1(w0) + w11 + sigma0(w3));
    Round(f, g, h, a, b, c, d, e, 0x53380d13, w3 += sigma1(w1) + w12 + sigma0(w4));
    Round(e, f, g, h, a, b, c, d, 0x650a7354, w4 += sigma1(w2) + w13 + sigma0(w5));
    Round(d, e, f, g, h, a, b, c, 0x766a0abb, w5 += sigma1(w3) + w14 + sigma0(w6));
    Round(c, d, e, f, g, h, a, b, 0x81c2c92e, w6 += sigma1(w4) + w15 + sigma0(w7));
    Round(b, c, d, e, f, g, h, a, 0x92722c85, w7 += sigma1(w5) + w0 + sigma0(w8));
    Round(a, b, c, d, e, f, g, h, 0xa2bfe8a1, w8 += sigma1(w6) + w1 + sigma0(w9));
    Round(h, a, b, c, d, e, f, g, 0xa81a664b, w9 += sigma1(w7) + w2 + sigma0(w10));
    Round(g, h, a, b, c, d, e, f, 0xc24b8b70, w10 += sigma1(w8) + w3 + sigma0(w11));
    Round(f, g, h, a, b, c, d, e, 0xc76c51a3, w11 += sigma1(w9) + w4 + sigma0(w12));
    Round(e, f, g, h, a, b, c, d, 0xd192e819, w12 += sigma1(w10) + w5 + sigma0(w13));
    Round(d, e, f, g, h, a, b, c, 0xd6990624, w13 += sigma1(w11) + w6 + sigma0(w14));
    Round(c, d, e, f, g, h, a, b, 0xf40e3585, w14 += sigma1(w12) + w7 + sigma0(w15));
    Round(b, c, d, e, f, g, h, a, 0x106aa070, w15 += sigma1(w13) + w8 + sigma0(w0));

    Round(a, b, c, d, e, f, g, h, 0x19a4c116, w0 += sigma1(w14) + w9 + sigma0(w1));
    Round(h, a, b, c, d, e, f, g, 0x1e376c08, w1 += sigma1(w15) + w10 + sigma0(w2));
    Round(g, h, a, b, c, d, e, f, 0x2748774c, w2 += sigma1(w0) + w11 + sigma0(w3));
    Round(f, g, h, a, b, c, d, e, 0x34b0bcb5, w3 += sigma1(w1) + w12 + sigma0(w4));
    Round(e, f, g, h, a, b, c, d, 0x391c0cb3, w4 += sigma1(w2) + w13 + sigma0(w5));
    Round(d, e, f, g, h, a, b, c, 0x4ed8aa4a, w5 += sigma1(w3) + w14 + sigma0(w6));
    Round(c, d, e, f, g, h, a, b, 0x5b9cca4f, w6 += sigma1(w4) + w15 + sigma0(w7));
    Round(b, c, d, e, f, g, h, a, 0x682e6ff3, w7 += sigma1(w5) + w0 + sigma0(w8));
    Round(a, b, c, d, e, f, g, h, 0x748f82ee, w8 += sigma1(w6) + w1 + sigma0(w9));
    Round(h, a, b, c, d, e, f, g, 0x78a5636f, w9 += sigma1(w7) + w2 + sigma0(w10));
    Round(g, h, a, b, c, d, e, f, 0x84c87814, w10 += sigma1(w8) + w3 + sigma0(w11));
    Round(f, g, h, a, b, c, d, e, 0x8cc70208, w11 += sigma1(w9) + w4 + sigma0(w12));
    Round(e, f, g, h, a, b, c, d, 0x90befffa, w12 += sigma1(w10) + w5 + sigma0(w13));
    Round(d, e, f, g, h, a, b, c, 0xa4506ceb, w13 += sigma1(w11) + w6 + sigma0(w14));
    Round(c, d, e, f, g, h, a, b, 0xbef9a3f7, w14 + sigma1(w12) + w7 + sigma0(w15));
    Round(b, c, d, e, f, g, h, a, 0xc67178f2, w15 + sigma1(w13) + w8 + sigma0(w0));

    s[0] += a;
    s[1] += b;
    s[2] += c;
    s[3] += d;
    s[4] += e;
    s[5] += f;
    s[6] += g;
    s[7] += h;
}

static void secp256k1_sha256_write(secp256k1_sha256_t *hash, const unsigned char *data, size_t len) {
    size_t bufsize = hash->bytes & 0x3F;
    hash->bytes += len;
    while (bufsize + len >= 64) {
        /* Fill the buffer, and process it. */
        memcpy(((unsigned char*)hash->buf) + bufsize, data, 64 - bufsize);
        data += 64 - bufsize;
        len -= 64 - bufsize;
        secp256k1_sha256_transform(hash->s, hash->buf);
        bufsize = 0;
    }
    if (len) {
        /* Fill the buffer with what remains. */
        memcpy(((unsigned char*)hash->buf) + bufsize, data, len);
    }
}

static void secp256k1_sha256_finalize(secp256k1_sha256_t *hash, unsigned char *out32) {
	unsigned char pad[64] = {0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint32_t sizedesc[2];
    uint32_t out[8];
    int i = 0;
    sizedesc[0] = BE32(hash->bytes >> 29);
    sizedesc[1] = BE32(hash->bytes << 3);
    secp256k1_sha256_write(hash, pad, 1 + ((119 - (hash->bytes % 64)) % 64));
    secp256k1_sha256_write(hash, (const unsigned char*)sizedesc, 8);
    for (i = 0; i < 8; i++) {
        out[i] = BE32(hash->s[i]);
        hash->s[i] = 0;
    }
    memcpy(out32, (const unsigned char*)out, 32);
}

static void secp256k1_hmac_sha256_initialize(secp256k1_hmac_sha256_t *hash, const unsigned char *key, size_t keylen)
{
	uint32_t rkey[16] = {0};

	for ( int i = 0; i < 8; i++ ) rkey[ i ] = ((uint32_t*)key)[ i ];

    secp256k1_sha256_initialize(&hash->outer);
	for ( int i = 0; i < 16; i++ ) rkey[ i ] ^= 0x5c5c5c5c;
    secp256k1_sha256_write(&hash->outer, (unsigned char *)rkey, 64);

    secp256k1_sha256_initialize(&hash->inner);
	for ( int i = 0; i < 16; i++ ) rkey[ i ] ^= 0x5c5c5c5c ^ 0x36363636;
    secp256k1_sha256_write(&hash->inner, (unsigned char *)rkey, 64);
}

static void secp256k1_hmac_sha256_write(secp256k1_hmac_sha256_t *hash, const unsigned char *data, size_t size) {
    secp256k1_sha256_write(&hash->inner, data, size);
}

static void secp256k1_hmac_sha256_finalize(secp256k1_hmac_sha256_t *hash, unsigned char *out32) {
    unsigned char temp[32];
    secp256k1_sha256_finalize(&hash->inner, temp);
    secp256k1_sha256_write(&hash->outer, temp, 32);
    secp256k1_sha256_finalize(&hash->outer, out32);
}


static void secp256k1_rfc6979_hmac_sha256_initialize(secp256k1_rfc6979_hmac_sha256_t *rng, const unsigned char *key, size_t keylen) {
    secp256k1_hmac_sha256_t hmac;
    const unsigned char zero[1] = {0x00};
    const unsigned char one[1] = {0x01};

	for ( int i = 0; i < 8; i++ )
	{
		rng->v[ i ] = 0x01010101; /* RFC6979 3.2.b. */
		rng->k[ i ] = 0x00000000; /* RFC6979 3.2.c. */
	}

    /* RFC6979 3.2.d. */
    secp256k1_hmac_sha256_initialize(&hmac, (unsigned char*)rng->k, 32);
    secp256k1_hmac_sha256_write(&hmac, (unsigned char*)rng->v, 32);
    secp256k1_hmac_sha256_write(&hmac, zero, 1);
    secp256k1_hmac_sha256_write(&hmac, key, keylen);
    secp256k1_hmac_sha256_finalize(&hmac, (unsigned char*)rng->k);
    secp256k1_hmac_sha256_initialize(&hmac, (unsigned char*)rng->k, 32);
    secp256k1_hmac_sha256_write(&hmac, (unsigned char*)rng->v, 32);
    secp256k1_hmac_sha256_finalize(&hmac, (unsigned char*)rng->v);

    /* RFC6979 3.2.f. */
    secp256k1_hmac_sha256_initialize(&hmac, (unsigned char*)rng->k, 32);
    secp256k1_hmac_sha256_write(&hmac, (unsigned char*)rng->v, 32);
    secp256k1_hmac_sha256_write(&hmac, one, 1);
    secp256k1_hmac_sha256_write(&hmac, key, keylen);
    secp256k1_hmac_sha256_finalize(&hmac, (unsigned char*)rng->k);
    secp256k1_hmac_sha256_initialize(&hmac, (unsigned char*)rng->k, 32);
    secp256k1_hmac_sha256_write(&hmac, (unsigned char*)rng->v, 32);
    secp256k1_hmac_sha256_finalize(&hmac, (unsigned char*)rng->v);
}

static void secp256k1_rfc6979_hmac_sha256_generate(secp256k1_rfc6979_hmac_sha256_t *rng, unsigned char *out, size_t outlen) {
    while (outlen > 0) {
        secp256k1_hmac_sha256_t hmac;
        int now = outlen;
        secp256k1_hmac_sha256_initialize(&hmac, (unsigned char*)rng->k, 32);
        secp256k1_hmac_sha256_write(&hmac, (unsigned char*)rng->v, 32);
        secp256k1_hmac_sha256_finalize(&hmac, (unsigned char*)rng->v);
        if (now > 32) {
            now = 32;
        }
        memcpy(out, (unsigned char*)rng->v, now);
        out += now;
        outlen -= now;
    }
}

#undef BE32
#undef Round
#undef sigma1
#undef sigma0
#undef Sigma1
#undef Sigma0
#undef Maj
#undef Ch

// {{{ secp256k1 constants
/* Limbs of the secp256k1 order. */
#define SECP256K1_N_0 ((uint32_t)0xD0364141UL)
#define SECP256K1_N_1 ((uint32_t)0xBFD25E8CUL)
#define SECP256K1_N_2 ((uint32_t)0xAF48A03BUL)
#define SECP256K1_N_3 ((uint32_t)0xBAAEDCE6UL)
#define SECP256K1_N_4 ((uint32_t)0xFFFFFFFEUL)
#define SECP256K1_N_5 ((uint32_t)0xFFFFFFFFUL)
#define SECP256K1_N_6 ((uint32_t)0xFFFFFFFFUL)
#define SECP256K1_N_7 ((uint32_t)0xFFFFFFFFUL)

/* Limbs of 2^256 minus the secp256k1 order. */
#define SECP256K1_N_C_0 (~SECP256K1_N_0 + 1)
#define SECP256K1_N_C_1 (~SECP256K1_N_1)
#define SECP256K1_N_C_2 (~SECP256K1_N_2)
#define SECP256K1_N_C_3 (~SECP256K1_N_3)
#define SECP256K1_N_C_4 (1)

/* Limbs of half the secp256k1 order. */
#define SECP256K1_N_H_0 ((uint32_t)0x681B20A0UL)
#define SECP256K1_N_H_1 ((uint32_t)0xDFE92F46UL)
#define SECP256K1_N_H_2 ((uint32_t)0x57A4501DUL)
#define SECP256K1_N_H_3 ((uint32_t)0x5D576E73UL)
#define SECP256K1_N_H_4 ((uint32_t)0xFFFFFFFFUL)
#define SECP256K1_N_H_5 ((uint32_t)0xFFFFFFFFUL)
#define SECP256K1_N_H_6 ((uint32_t)0xFFFFFFFFUL)
#define SECP256K1_N_H_7 ((uint32_t)0x7FFFFFFFUL)
// }}}

// {{{ secret key verification
SECP256K1_INLINE uint32_t secp256k1_scalar_check_overflow( uint32_t *a )
{
	uint32_t yes = 0;
	uint32_t no = 0;
	no |= (a[7] < SECP256K1_N_7); /* No need for a > check. */
	no |= (a[6] < SECP256K1_N_6); /* No need for a > check. */
	no |= (a[5] < SECP256K1_N_5); /* No need for a > check. */
	no |= (a[4] < SECP256K1_N_4);
	yes |= (a[4] > SECP256K1_N_4) & ~no;
	no |= (a[3] < SECP256K1_N_3) & ~yes;
	yes |= (a[3] > SECP256K1_N_3) & ~no;
	no |= (a[2] < SECP256K1_N_2) & ~yes;
	yes |= (a[2] > SECP256K1_N_2) & ~no;
	no |= (a[1] < SECP256K1_N_1) & ~yes;
	yes |= (a[1] > SECP256K1_N_1) & ~no;
	yes |= (a[0] >= SECP256K1_N_0) & ~no;
	return yes;
}

SECP256K1_INLINE uint32_t secp256k1_scalar_reduce( uint32_t *r, uint32_t overflow )
{
	uint64_t t;

	t = (uint64_t)r[0] + overflow * SECP256K1_N_C_0;
	r[0] = t & 0xFFFFFFFFUL; t >>= 32;
	t += (uint64_t)r[1] + overflow * SECP256K1_N_C_1;
	r[1] = t & 0xFFFFFFFFUL; t >>= 32;
	t += (uint64_t)r[2] + overflow * SECP256K1_N_C_2;
	r[2] = t & 0xFFFFFFFFUL; t >>= 32;
	t += (uint64_t)r[3] + overflow * SECP256K1_N_C_3;
	r[3] = t & 0xFFFFFFFFUL; t >>= 32;
	t += (uint64_t)r[4] + overflow * SECP256K1_N_C_4;
	r[4] = t & 0xFFFFFFFFUL; t >>= 32;
	t += (uint64_t)r[5];
	r[5] = t & 0xFFFFFFFFUL; t >>= 32;
	t += (uint64_t)r[6];
	r[6] = t & 0xFFFFFFFFUL; t >>= 32;
	t += (uint64_t)r[7];
	r[7] = t & 0xFFFFFFFFUL;

	return overflow;
}

SECP256K1_INLINE uint32_t secp256k1_scalar_set_b32( uint32_t *r, unsigned char *b32 )
{
	r[0] = (uint32_t)b32[31] | (uint32_t)b32[30] << 8 | (uint32_t)b32[29] << 16 | (uint32_t)b32[28] << 24;
	r[1] = (uint32_t)b32[27] | (uint32_t)b32[26] << 8 | (uint32_t)b32[25] << 16 | (uint32_t)b32[24] << 24;
	r[2] = (uint32_t)b32[23] | (uint32_t)b32[22] << 8 | (uint32_t)b32[21] << 16 | (uint32_t)b32[20] << 24;
	r[3] = (uint32_t)b32[19] | (uint32_t)b32[18] << 8 | (uint32_t)b32[17] << 16 | (uint32_t)b32[16] << 24;
	r[4] = (uint32_t)b32[15] | (uint32_t)b32[14] << 8 | (uint32_t)b32[13] << 16 | (uint32_t)b32[12] << 24;
	r[5] = (uint32_t)b32[11] | (uint32_t)b32[10] << 8 | (uint32_t)b32[9] << 16 | (uint32_t)b32[8] << 24;
	r[6] = (uint32_t)b32[7] | (uint32_t)b32[6] << 8 | (uint32_t)b32[5] << 16 | (uint32_t)b32[4] << 24;
	r[7] = (uint32_t)b32[3] | (uint32_t)b32[2] << 8 | (uint32_t)b32[1] << 16 | (uint32_t)b32[0] << 24;

    return secp256k1_scalar_reduce( r, secp256k1_scalar_check_overflow( r ) );
}

SECP256K1_INLINE void secp256k1_scalar_get_b32(unsigned char *bin, const uint32_t *a) {
    bin[0] = a[7] >> 24; bin[1] = a[7] >> 16; bin[2] = a[7] >> 8; bin[3] = a[7];
    bin[4] = a[6] >> 24; bin[5] = a[6] >> 16; bin[6] = a[6] >> 8; bin[7] = a[6];
    bin[8] = a[5] >> 24; bin[9] = a[5] >> 16; bin[10] = a[5] >> 8; bin[11] = a[5];
    bin[12] = a[4] >> 24; bin[13] = a[4] >> 16; bin[14] = a[4] >> 8; bin[15] = a[4];
    bin[16] = a[3] >> 24; bin[17] = a[3] >> 16; bin[18] = a[3] >> 8; bin[19] = a[3];
    bin[20] = a[2] >> 24; bin[21] = a[2] >> 16; bin[22] = a[2] >> 8; bin[23] = a[2];
    bin[24] = a[1] >> 24; bin[25] = a[1] >> 16; bin[26] = a[1] >> 8; bin[27] = a[1];
    bin[28] = a[0] >> 24; bin[29] = a[0] >> 16; bin[30] = a[0] >> 8; bin[31] = a[0];
}

// }}}

// {{{ public key creation
SECP256K1_INLINE void secp256k1_scalar_add( uint32_t *r, uint32_t *a )
{
	uint32_t overflow;
	uint64_t t = (uint64_t)a[0] + 0x842f1fb6;
	r[0] = t & 0xFFFFFFFFUL; t >>= 32;
	t += (uint64_t)a[1] + 0x32b75595;
	r[1] = t & 0xFFFFFFFFUL; t >>= 32;
	t += (uint64_t)a[2] + 0x3e5afcd9;
	r[2] = t & 0xFFFFFFFFUL; t >>= 32;
	t += (uint64_t)a[3] + 0x4f4d95a4;
	r[3] = t & 0xFFFFFFFFUL; t >>= 32;
	t += (uint64_t)a[4] + 0xef5be82d;
	r[4] = t & 0xFFFFFFFFUL; t >>= 32;
	t += (uint64_t)a[5] + 0x92fd7d90;
	r[5] = t & 0xFFFFFFFFUL; t >>= 32;
	t += (uint64_t)a[6] + 0x7a5629e7;
	r[6] = t & 0xFFFFFFFFUL; t >>= 32;
	t += (uint64_t)a[7] + 0x7c3f0f58;
	r[7] = t & 0xFFFFFFFFUL; t >>= 32;
	overflow = t + secp256k1_scalar_check_overflow( r );

	secp256k1_scalar_reduce( r, overflow );
}

SECP256K1_INLINE uint32_t secp256k1_scalar_add_big( uint32_t *r, uint32_t *a, uint32_t *b )
{
    uint64_t t;
    t  = (uint64_t)a[0] + b[0]; r[0] = t & 0xFFFFFFFFUL; t >>= 32;
    t += (uint64_t)a[1] + b[1]; r[1] = t & 0xFFFFFFFFUL; t >>= 32;
    t += (uint64_t)a[2] + b[2]; r[2] = t & 0xFFFFFFFFUL; t >>= 32;
    t += (uint64_t)a[3] + b[3]; r[3] = t & 0xFFFFFFFFUL; t >>= 32;
    t += (uint64_t)a[4] + b[4]; r[4] = t & 0xFFFFFFFFUL; t >>= 32;
    t += (uint64_t)a[5] + b[5]; r[5] = t & 0xFFFFFFFFUL; t >>= 32;
    t += (uint64_t)a[6] + b[6]; r[6] = t & 0xFFFFFFFFUL; t >>= 32;
    t += (uint64_t)a[7] + b[7]; r[7] = t & 0xFFFFFFFFUL; t >>= 32;

    /* Make secp256k1_scalar_check_overflow conditional */
    if ( t > 0 ) { return secp256k1_scalar_reduce(r, 1); }
    if ( secp256k1_scalar_check_overflow(r) ) { return secp256k1_scalar_reduce(r, 1); }
    return 0;
}

/* Inspired by the macros in OpenSSL's crypto/bn/asm/x86_64-gcc.c. */

/** Add a*b to the number defined by (c0,c1,c2). c2 must never overflow. */
#define muladd(a,b) { \
    uint32_t tl, th; \
    { \
        uint64_t t = (uint64_t)a * b; \
        th = t >> 32;         /* at most 0xFFFFFFFE */ \
        tl = t; \
    } \
    c0 += tl;                 /* overflow is handled on the next line */ \
    th += (c0 < tl) ? 1 : 0;  /* at most 0xFFFFFFFF */ \
    c1 += th;                 /* overflow is handled on the next line */ \
    c2 += (c1 < th) ? 1 : 0;  /* never overflows by contract (verified in the next line) */ \
}

/** Add a*b to the number defined by (c0,c1). c1 must never overflow. */
#define muladd_fast(a,b) { \
    uint32_t tl, th; \
    { \
        uint64_t t = (uint64_t)a * b; \
        th = t >> 32;         /* at most 0xFFFFFFFE */ \
        tl = t; \
    } \
    c0 += tl;                 /* overflow is handled on the next line */ \
    th += (c0 < tl) ? 1 : 0;  /* at most 0xFFFFFFFF */ \
    c1 += th;                 /* never overflows by contract (verified in the next line) */ \
}

/** Add 2*a*b to the number defined by (c0,c1,c2). c2 must never overflow. */
#define muladd2(a,b) { \
    uint32_t tl, th, th2, tl2; \
    { \
        uint64_t t = (uint64_t)a * b; \
        th = t >> 32;               /* at most 0xFFFFFFFE */ \
        tl = t; \
    } \
    th2 = th + th;                  /* at most 0xFFFFFFFE (in case th was 0x7FFFFFFF) */ \
    c2 += (th2 < th) ? 1 : 0;       /* never overflows by contract (verified the next line) */ \
    tl2 = tl + tl;                  /* at most 0xFFFFFFFE (in case the lowest 63 bits of tl were 0x7FFFFFFF) */ \
    th2 += (tl2 < tl) ? 1 : 0;      /* at most 0xFFFFFFFF */ \
    c0 += tl2;                      /* overflow is handled on the next line */ \
    th2 += (c0 < tl2) ? 1 : 0;      /* second overflow is handled on the next line */ \
    c2 += (c0 < tl2) & (th2 == 0);  /* never overflows by contract (verified the next line) */ \
    c1 += th2;                      /* overflow is handled on the next line */ \
    c2 += (c1 < th2) ? 1 : 0;       /* never overflows by contract (verified the next line) */ \
}

/** Add a to the number defined by (c0,c1,c2). c2 must never overflow. */
#define sumadd(a) { \
    unsigned int over; \
    c0 += (a);                  /* overflow is handled on the next line */ \
    over = (c0 < (a)) ? 1 : 0; \
    c1 += over;                 /* overflow is handled on the next line */ \
    c2 += (c1 < over) ? 1 : 0;  /* never overflows by contract */ \
}

/** Add a to the number defined by (c0,c1). c1 must never overflow, c2 must be zero. */
#define sumadd_fast(a) { \
    c0 += (a);                 /* overflow is handled on the next line */ \
    c1 += (c0 < (a)) ? 1 : 0;  /* never overflows by contract (verified the next line) */ \
}

/** Extract the lowest 32 bits of (c0,c1,c2) into n, and left shift the number 32 bits. */
#define extract(n) { \
    (n) = c0; \
    c0 = c1; \
    c1 = c2; \
    c2 = 0; \
}

/** Extract the lowest 32 bits of (c0,c1,c2) into n, and left shift the number 32 bits. c2 is required to be zero. */
#define extract_fast(n) { \
    (n) = c0; \
    c0 = c1; \
    c1 = 0; \
}

SECP256K1_INLINE void secp256k1_scalar_mul_512( uint32_t *l, const uint32_t *a, const uint32_t *b )
{
	/* 96 bit accumulator. */
	uint32_t c0 = 0, c1 = 0, c2 = 0;

	/* l[0..15] = a[0..7] * b[0..7]. */
	muladd_fast(a[0], b[0]);
	extract_fast(l[0]);
	muladd(a[0], b[1]);
	muladd(a[1], b[0]);
	extract(l[1]);
	muladd(a[0], b[2]);
	muladd(a[1], b[1]);
	muladd(a[2], b[0]);
	extract(l[2]);
	muladd(a[0], b[3]);
	muladd(a[1], b[2]);
	muladd(a[2], b[1]);
	muladd(a[3], b[0]);
	extract(l[3]);
	muladd(a[0], b[4]);
	muladd(a[1], b[3]);
	muladd(a[2], b[2]);
	muladd(a[3], b[1]);
	muladd(a[4], b[0]);
	extract(l[4]);
	muladd(a[0], b[5]);
	muladd(a[1], b[4]);
	muladd(a[2], b[3]);
	muladd(a[3], b[2]);
	muladd(a[4], b[1]);
	muladd(a[5], b[0]);
	extract(l[5]);
	muladd(a[0], b[6]);
	muladd(a[1], b[5]);
	muladd(a[2], b[4]);
	muladd(a[3], b[3]);
	muladd(a[4], b[2]);
	muladd(a[5], b[1]);
	muladd(a[6], b[0]);
	extract(l[6]);
	muladd(a[0], b[7]);
	muladd(a[1], b[6]);
	muladd(a[2], b[5]);
	muladd(a[3], b[4]);
	muladd(a[4], b[3]);
	muladd(a[5], b[2]);
	muladd(a[6], b[1]);
	muladd(a[7], b[0]);
	extract(l[7]);
	muladd(a[1], b[7]);
	muladd(a[2], b[6]);
	muladd(a[3], b[5]);
	muladd(a[4], b[4]);
	muladd(a[5], b[3]);
	muladd(a[6], b[2]);
	muladd(a[7], b[1]);
	extract(l[8]);
	muladd(a[2], b[7]);
	muladd(a[3], b[6]);
	muladd(a[4], b[5]);
	muladd(a[5], b[4]);
	muladd(a[6], b[3]);
	muladd(a[7], b[2]);
	extract(l[9]);
	muladd(a[3], b[7]);
	muladd(a[4], b[6]);
	muladd(a[5], b[5]);
	muladd(a[6], b[4]);
	muladd(a[7], b[3]);
	extract(l[10]);
	muladd(a[4], b[7]);
	muladd(a[5], b[6]);
	muladd(a[6], b[5]);
	muladd(a[7], b[4]);
	extract(l[11]);
	muladd(a[5], b[7]);
	muladd(a[6], b[6]);
	muladd(a[7], b[5]);
	extract(l[12]);
	muladd(a[6], b[7]);
	muladd(a[7], b[6]);
	extract(l[13]);
	muladd_fast(a[7], b[7]);
	extract_fast(l[14]);

	l[15] = c0;
}

SECP256K1_INLINE void secp256k1_scalar_reduce_512( uint32_t *r, const uint32_t *l )
{
	uint64_t c;
	uint32_t n0 = l[8], n1 = l[9], n2 = l[10], n3 = l[11], n4 = l[12], n5 = l[13], n6 = l[14], n7 = l[15];
	uint32_t m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12;
	uint32_t p0, p1, p2, p3, p4, p5, p6, p7, p8;

	/* 96 bit accumulator. */
	uint32_t c0, c1, c2;

	/* Reduce 512 bits into 385. */
	/* m[0..12] = l[0..7] + n[0..7] * SECP256K1_N_C. */
	c0 = l[0]; c1 = 0; c2 = 0;
	muladd_fast(n0, SECP256K1_N_C_0);
	extract_fast(m0);
	sumadd_fast(l[1]);
	muladd(n1, SECP256K1_N_C_0);
	muladd(n0, SECP256K1_N_C_1);
	extract(m1);
	sumadd(l[2]);
	muladd(n2, SECP256K1_N_C_0);
	muladd(n1, SECP256K1_N_C_1);
	muladd(n0, SECP256K1_N_C_2);
	extract(m2);
	sumadd(l[3]);
	muladd(n3, SECP256K1_N_C_0);
	muladd(n2, SECP256K1_N_C_1);
	muladd(n1, SECP256K1_N_C_2);
	muladd(n0, SECP256K1_N_C_3);
	extract(m3);
	sumadd(l[4]);
	muladd(n4, SECP256K1_N_C_0);
	muladd(n3, SECP256K1_N_C_1);
	muladd(n2, SECP256K1_N_C_2);
	muladd(n1, SECP256K1_N_C_3);
	sumadd(n0);
	extract(m4);
	sumadd(l[5]);
	muladd(n5, SECP256K1_N_C_0);
	muladd(n4, SECP256K1_N_C_1);
	muladd(n3, SECP256K1_N_C_2);
	muladd(n2, SECP256K1_N_C_3);
	sumadd(n1);
	extract(m5);
	sumadd(l[6]);
	muladd(n6, SECP256K1_N_C_0);
	muladd(n5, SECP256K1_N_C_1);
	muladd(n4, SECP256K1_N_C_2);
	muladd(n3, SECP256K1_N_C_3);
	sumadd(n2);
	extract(m6);
	sumadd(l[7]);
	muladd(n7, SECP256K1_N_C_0);
	muladd(n6, SECP256K1_N_C_1);
	muladd(n5, SECP256K1_N_C_2);
	muladd(n4, SECP256K1_N_C_3);
	sumadd(n3);
	extract(m7);
	muladd(n7, SECP256K1_N_C_1);
	muladd(n6, SECP256K1_N_C_2);
	muladd(n5, SECP256K1_N_C_3);
	sumadd(n4);
	extract(m8);
	muladd(n7, SECP256K1_N_C_2);
	muladd(n6, SECP256K1_N_C_3);
	sumadd(n5);
	extract(m9);
	muladd(n7, SECP256K1_N_C_3);
	sumadd(n6);
	extract(m10);
	sumadd_fast(n7);
	extract_fast(m11);
	m12 = c0;

	/* Reduce 385 bits into 258. */
	/* p[0..8] = m[0..7] + m[8..12] * SECP256K1_N_C. */
	c0 = m0; c1 = 0; c2 = 0;
	muladd_fast(m8, SECP256K1_N_C_0);
	extract_fast(p0);
	sumadd_fast(m1);
	muladd(m9, SECP256K1_N_C_0);
	muladd(m8, SECP256K1_N_C_1);
	extract(p1);
	sumadd(m2);
	muladd(m10, SECP256K1_N_C_0);
	muladd(m9, SECP256K1_N_C_1);
	muladd(m8, SECP256K1_N_C_2);
	extract(p2);
	sumadd(m3);
	muladd(m11, SECP256K1_N_C_0);
	muladd(m10, SECP256K1_N_C_1);
	muladd(m9, SECP256K1_N_C_2);
	muladd(m8, SECP256K1_N_C_3);
	extract(p3);
	sumadd(m4);
	muladd(m12, SECP256K1_N_C_0);
	muladd(m11, SECP256K1_N_C_1);
	muladd(m10, SECP256K1_N_C_2);
	muladd(m9, SECP256K1_N_C_3);
	sumadd(m8);
	extract(p4);
	sumadd(m5);
	muladd(m12, SECP256K1_N_C_1);
	muladd(m11, SECP256K1_N_C_2);
	muladd(m10, SECP256K1_N_C_3);
	sumadd(m9);
	extract(p5);
	sumadd(m6);
	muladd(m12, SECP256K1_N_C_2);
	muladd(m11, SECP256K1_N_C_3);
	sumadd(m10);
	extract(p6);
	sumadd_fast(m7);
	muladd_fast(m12, SECP256K1_N_C_3);
	sumadd_fast(m11);
	extract_fast(p7);
	p8 = c0 + m12;

	/* Reduce 258 bits into 256. */
	/* r[0..7] = p[0..7] + p[8] * SECP256K1_N_C. */
	c = p0 + (uint64_t)SECP256K1_N_C_0 * p8;
	r[0] = c & 0xFFFFFFFFUL; c >>= 32;
	c += p1 + (uint64_t)SECP256K1_N_C_1 * p8;
	r[1] = c & 0xFFFFFFFFUL; c >>= 32;
	c += p2 + (uint64_t)SECP256K1_N_C_2 * p8;
	r[2] = c & 0xFFFFFFFFUL; c >>= 32;
	c += p3 + (uint64_t)SECP256K1_N_C_3 * p8;
	r[3] = c & 0xFFFFFFFFUL; c >>= 32;
	c += p4 + (uint64_t)p8;
	r[4] = c & 0xFFFFFFFFUL; c >>= 32;
	c += p5;
	r[5] = c & 0xFFFFFFFFUL; c >>= 32;
	c += p6;
	r[6] = c & 0xFFFFFFFFUL; c >>= 32;
	c += p7;
	r[7] = c & 0xFFFFFFFFUL; c >>= 32;

	/* Final reduction of r. */
	secp256k1_scalar_reduce(r, c + secp256k1_scalar_check_overflow(r));
}

SECP256K1_INLINE void secp256k1_scalar_mul( uint32_t *r, const uint32_t *a, const uint32_t *b )
{
	uint32_t l[16];
	secp256k1_scalar_mul_512( l, a, b );
	secp256k1_scalar_reduce_512( r, l );
}

SECP256K1_INLINE uint32_t secp256k1_scalar_get_bits( uint32_t *a, uint32_t offset, uint32_t count )
{
	return ( a[ offset >> 5 ] >> ( offset & 0x1F ) ) & ( ( 1 << count ) - 1 );
}

#define secp256k1_fe_set_int( r, a ) \
{\
    r[0] = a;\
    r[1] = r[2] = r[3] = r[4] = r[5] = r[6] = r[7] = r[8] = r[9] = 0;\
}

SECP256K1_INLINE void secp256k1_fe_storage_cmov( uint32_t *r, __constant uint32_t *a )
{
	r[0] = a[0];
	r[1] = a[1];
	r[2] = a[2];
	r[3] = a[3];
	r[4] = a[4];
	r[5] = a[5];
	r[6] = a[6];
	r[7] = a[7];
}

#define secp256k1_fe_from_storage( r, a ) \
{\
	r[0] = a[0] & 0x3FFFFFFUL;\
	r[1] = a[0] >> 26 | ((a[1] << 6) & 0x3FFFFFFUL);\
	r[2] = a[1] >> 20 | ((a[2] << 12) & 0x3FFFFFFUL);\
	r[3] = a[2] >> 14 | ((a[3] << 18) & 0x3FFFFFFUL);\
	r[4] = a[3] >> 8 | ((a[4] << 24) & 0x3FFFFFFUL);\
	r[5] = (a[4] >> 2) & 0x3FFFFFFUL;\
	r[6] = a[4] >> 28 | ((a[5] << 4) & 0x3FFFFFFUL);\
	r[7] = a[5] >> 22 | ((a[6] << 10) & 0x3FFFFFFUL);\
	r[8] = a[6] >> 16 | ((a[7] << 16) & 0x3FFFFFFUL);\
	r[9] = a[7] >> 10;\
}

#define volatile
#define amd_init(a,b,c) 0
#define mad_opt( r, a, b ) r += (uint64_t)a * (uint32_t)b
#define madi_opt( r, a, b ) r += (int64_t)a * (int32_t)b

#define secp256k1_ge_from_storage( r, a ) \
{\
    secp256k1_fe_from_storage( (r)->x, (a)->x );\
    secp256k1_fe_from_storage( (r)->y, (a)->y );\
}

#define secp256k1_fe_sqr_inner \
{\
    uint64_t c, d;\
    uint32_t u0, u1, u2, u3, u4, u5, u6, u7, u8;\
    uint32_t t9, t0, t1, t2, t3, t4, t5, t6, t7;\
    const uint32_t M = 0x3FFFFFFUL, R0 = 0x3D10UL, R1 = 0x400UL;\
\
	volatile uint32_t carry = amd_init( a[0], a[0], a[0] );\
	d = 0;\
	mad_opt( d, (a[0]*2), (a[9]) );\
	mad_opt( d, (a[1]*2), (a[8]) );\
	mad_opt( d, (a[2]*2), (a[7]) );\
	mad_opt( d, (a[3]*2), (a[6]) );\
	mad_opt( d, (a[4]*2), (a[5]) );\
\
    t9 = d & M; d >>= 26;\
\
	c = 0;\
	mad_opt( c, (a[0]), (a[0]) );\
\
	mad_opt( d, (a[1]*2), (a[9]) );\
	mad_opt( d, (a[2]*2), (a[8]) );\
	mad_opt( d, (a[3]*2), (a[7]) );\
	mad_opt( d, (a[4]*2), (a[6]) );\
	mad_opt( d, (a[5]),   (a[5]) );\
\
    u0 = d & M; d >>= 26; mad_opt( c, (u0), (R0) );\
    t0 = c & M; c >>= 26; mad_opt( c, (u0), (R1) );\
\
	mad_opt( c, (a[0]*2), (a[1]) );\
\
	mad_opt( d, (a[2]*2), (a[9]) );\
	mad_opt( d, (a[3]*2), (a[8]) );\
	mad_opt( d, (a[4]*2), (a[7]) );\
	mad_opt( d, (a[5]*2), (a[6]) );\
\
    u1 = d & M; d >>= 26; mad_opt( c, (u1), (R0) );\
    t1 = c & M; c >>= 26; mad_opt( c, (u1), (R1) );\
\
	mad_opt( c, (a[0]*2), (a[2]) );\
	mad_opt( c, (a[1]),   (a[1]) );\
\
	mad_opt( d, (a[3]*2), (a[9]) );\
	mad_opt( d, (a[4]*2), (a[8]) );\
	mad_opt( d, (a[5]*2), (a[7]) );\
	mad_opt( d, (a[6]),   (a[6]) );\
\
    u2 = d & M; d >>= 26; mad_opt( c, (u2), (R0) );\
    t2 = c & M; c >>= 26; mad_opt( c, (u2), (R1) );\
\
	mad_opt( c, (a[0]*2), (a[3]) );\
	mad_opt( c, (a[1]*2), (a[2]) );\
\
	mad_opt( d, (a[4]*2), (a[9]) );\
	mad_opt( d, (a[5]*2), (a[8]) );\
	mad_opt( d, (a[6]*2), (a[7]) );\
\
    u3 = d & M; d >>= 26; mad_opt( c, (u3), (R0) );\
    t3 = c & M; c >>= 26; mad_opt( c, (u3), (R1) );\
\
	mad_opt( c, (a[0]*2), (a[4]) );\
	mad_opt( c, (a[1]*2), (a[3]) );\
	mad_opt( c, (a[2]),   (a[2]) );\
\
	mad_opt( d, (a[5]*2), (a[9]) );\
	mad_opt( d, (a[6]*2), (a[8]) );\
	mad_opt( d, (a[7]),   (a[7]) );\
\
    u4 = d & M; d >>= 26; mad_opt( c, (u4), (R0) );\
    t4 = c & M; c >>= 26; mad_opt( c, (u4), (R1) );\
\
	mad_opt( c, (a[0]*2), (a[5]) );\
	mad_opt( c, (a[1]*2), (a[4]) );\
	mad_opt( c, (a[2]*2), (a[3]) );\
\
	mad_opt( d, (a[6]*2), (a[9]) );\
	mad_opt( d, (a[7]*2), (a[8]) );\
\
    u5 = d & M; d >>= 26; mad_opt( c, (u5), (R0) );\
    t5 = c & M; c >>= 26; mad_opt( c, (u5), (R1) );\
\
	mad_opt( c, (a[0]*2), (a[6]) );\
	mad_opt( c, (a[1]*2), (a[5]) );\
	mad_opt( c, (a[2]*2), (a[4]) );\
	mad_opt( c, (a[3]),   (a[3]) );\
\
	mad_opt( d, (a[7]*2), (a[9]) );\
	mad_opt( d, (a[8]),   (a[8]) );\
\
    u6 = d & M; d >>= 26; mad_opt( c, (u6), (R0) );\
    t6 = c & M; c >>= 26; mad_opt( c, (u6), (R1) );\
\
	mad_opt( c, (a[0]*2), (a[7]) );\
	mad_opt( c, (a[1]*2), (a[6]) );\
	mad_opt( c, (a[2]*2), (a[5]) );\
	mad_opt( c, (a[3]*2), (a[4]) );\
\
	mad_opt( d, (a[8]*2), (a[9]) );\
    u7 = d & M; d >>= 26; mad_opt( c, (u7), (R0) );\
    t7 = c & M; c >>= 26; mad_opt( c, (u7), (R1) );\
\
	mad_opt( c, (a[0]*2), (a[8]) );\
	mad_opt( c, (a[1]*2), (a[7]) );\
	mad_opt( c, (a[2]*2), (a[6]) );\
	mad_opt( c, (a[3]*2), (a[5]) );\
	mad_opt( c, (a[4]),   (a[4]) );\
\
	mad_opt( d, (a[9]), (a[9]) );\
\
    u8 = d & M; d >>= 26; mad_opt( c, (u8), (R0) );\
\
    r[3] = t3;\
    r[4] = t4;\
    r[5] = t5;\
    r[6] = t6;\
    r[7] = t7;\
    r[8] = c & M; c >>= 26; mad_opt( c, (u8), (R1) );\
\
    c   += d * R0 + t9;\
\
    r[9] = c & (M >> 4); c >>= 22; c += d * (R1 << 4);\
\
    d    = c * (R0 >> 4) + t0;\
    r[0] = d & M; d >>= 26;\
\
    d   += c * (R1 >> 4) + t1;\
\
    r[1] = d & M; d >>= 26;\
\
    d   += t2;\
\
    r[2] = d;\
}

SECP256K1_INLINE void secp256k1_fe_normalize_weak( uint32_t *r )
{
    uint32_t t0 = r[0], t1 = r[1], t2 = r[2], t3 = r[3], t4 = r[4],
             t5 = r[5], t6 = r[6], t7 = r[7], t8 = r[8], t9 = r[9];

    /* Reduce t9 at the start so there will be at most a single carry from the first pass */
    uint32_t x = t9 >> 22; t9 &= 0x03FFFFFUL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x3D1UL; t1 += (x << 6);
    t1 += (t0 >> 26); t0 &= 0x3FFFFFFUL;
    t2 += (t1 >> 26); t1 &= 0x3FFFFFFUL;
    t3 += (t2 >> 26); t2 &= 0x3FFFFFFUL;
    t4 += (t3 >> 26); t3 &= 0x3FFFFFFUL;
    t5 += (t4 >> 26); t4 &= 0x3FFFFFFUL;
    t6 += (t5 >> 26); t5 &= 0x3FFFFFFUL;
    t7 += (t6 >> 26); t6 &= 0x3FFFFFFUL;
    t8 += (t7 >> 26); t7 &= 0x3FFFFFFUL;
    t9 += (t8 >> 26); t8 &= 0x3FFFFFFUL;

    r[0] = t0; r[1] = t1; r[2] = t2; r[3] = t3; r[4] = t4;
    r[5] = t5; r[6] = t6; r[7] = t7; r[8] = t8; r[9] = t9;
}

SECP256K1_INLINE void secp256k1_fe_normalize( uint32_t *r )
{
    uint32_t t0 = r[0], t1 = r[1], t2 = r[2], t3 = r[3], t4 = r[4],
             t5 = r[5], t6 = r[6], t7 = r[7], t8 = r[8], t9 = r[9];

    /* Reduce t9 at the start so there will be at most a single carry from the first pass */
    uint32_t m;
    uint32_t x = t9 >> 22; t9 &= 0x03FFFFFUL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x3D1UL; t1 += (x << 6);
    t1 += (t0 >> 26); t0 &= 0x3FFFFFFUL;
    t2 += (t1 >> 26); t1 &= 0x3FFFFFFUL;
    t3 += (t2 >> 26); t2 &= 0x3FFFFFFUL; m = t2;
    t4 += (t3 >> 26); t3 &= 0x3FFFFFFUL; m &= t3;
    t5 += (t4 >> 26); t4 &= 0x3FFFFFFUL; m &= t4;
    t6 += (t5 >> 26); t5 &= 0x3FFFFFFUL; m &= t5;
    t7 += (t6 >> 26); t6 &= 0x3FFFFFFUL; m &= t6;
    t8 += (t7 >> 26); t7 &= 0x3FFFFFFUL; m &= t7;
    t9 += (t8 >> 26); t8 &= 0x3FFFFFFUL; m &= t8;

    /* At most a single final reduction is needed; check if the value is >= the field characteristic */
    x = (t9 >> 22) | ((t9 == 0x03FFFFFUL) & (m == 0x3FFFFFFUL)
        & ((t1 + 0x40UL + ((t0 + 0x3D1UL) >> 26)) > 0x3FFFFFFUL));

    /* Apply the final reduction (for constant-time behaviour, we do it always) */
    t0 += x * 0x3D1UL; t1 += (x << 6);
    t1 += (t0 >> 26); t0 &= 0x3FFFFFFUL;
    t2 += (t1 >> 26); t1 &= 0x3FFFFFFUL;
    t3 += (t2 >> 26); t2 &= 0x3FFFFFFUL;
    t4 += (t3 >> 26); t3 &= 0x3FFFFFFUL;
    t5 += (t4 >> 26); t4 &= 0x3FFFFFFUL;
    t6 += (t5 >> 26); t5 &= 0x3FFFFFFUL;
    t7 += (t6 >> 26); t6 &= 0x3FFFFFFUL;
    t8 += (t7 >> 26); t7 &= 0x3FFFFFFUL;
    t9 += (t8 >> 26); t8 &= 0x3FFFFFFUL;

    /* Mask off the possible multiple of 2^256 from the final reduction */
    t9 &= 0x03FFFFFUL;

    r[0] = t0; r[1] = t1; r[2] = t2; r[3] = t3; r[4] = t4;
    r[5] = t5; r[6] = t6; r[7] = t7; r[8] = t8; r[9] = t9;
}

SECP256K1_INLINE void secp256k1_fe_normalize_var( uint32_t *r )
{
	uint32_t t0 = r[0], t1 = r[1], t2 = r[2], t3 = r[3], t4 = r[4],
				t5 = r[5], t6 = r[6], t7 = r[7], t8 = r[8], t9 = r[9];

	/* Reduce t9 at the start so there will be at most a single carry from the first pass */
	uint32_t m;
	uint32_t x = t9 >> 22; t9 &= 0x03FFFFFUL;

	/* The first pass ensures the magnitude is 1, ... */
	t0 += x * 0x3D1UL; t1 += (x << 6);
	t1 += (t0 >> 26); t0 &= 0x3FFFFFFUL;
	t2 += (t1 >> 26); t1 &= 0x3FFFFFFUL;
	t3 += (t2 >> 26); t2 &= 0x3FFFFFFUL; m = t2;
	t4 += (t3 >> 26); t3 &= 0x3FFFFFFUL; m &= t3;
	t5 += (t4 >> 26); t4 &= 0x3FFFFFFUL; m &= t4;
	t6 += (t5 >> 26); t5 &= 0x3FFFFFFUL; m &= t5;
	t7 += (t6 >> 26); t6 &= 0x3FFFFFFUL; m &= t6;
	t8 += (t7 >> 26); t7 &= 0x3FFFFFFUL; m &= t7;
	t9 += (t8 >> 26); t8 &= 0x3FFFFFFUL; m &= t8;

	r[0] = t0; r[1] = t1; r[2] = t2; r[3] = t3; r[4] = t4;
	r[5] = t5; r[6] = t6; r[7] = t7; r[8] = t8; r[9] = t9;
}

#define secp256k1_fe_mul_inner \
{\
    uint64_t c, d;\
    uint32_t u0, u1, u2, u3, u4, u5, u6, u7, u8;\
    uint32_t t9, t1, t0, t2, t3, t4, t5, t6, t7;\
    const uint32_t M = 0x3FFFFFFUL, R0 = 0x3D10UL, R1 = 0x400UL;\
\
	volatile uint32_t carry = amd_init( a[0], a[0], a[0] );\
	d = 0;\
	c = 0;\
	mad_opt( d, (a[0]), (b[9]) );\
	mad_opt( d, (a[1]), (b[8]) );\
	mad_opt( d, (a[2]), (b[7]) );\
	mad_opt( d, (a[3]), (b[6]) );\
	mad_opt( d, (a[4]), (b[5]) );\
	mad_opt( d, (a[5]), (b[4]) );\
	mad_opt( d, (a[6]), (b[3]) );\
	mad_opt( d, (a[7]), (b[2]) );\
	mad_opt( d, (a[8]), (b[1]) );\
	mad_opt( d, (a[9]), (b[0]) );\
\
    t9 = d & M; d >>= 26;\
	mad_opt( c, (a[0]), (b[0]) );\
\
	mad_opt( d, (a[1]), (b[9]) );\
	mad_opt( d, (a[2]), (b[8]) );\
	mad_opt( d, (a[3]), (b[7]) );\
	mad_opt( d, (a[4]), (b[6]) );\
	mad_opt( d, (a[5]), (b[5]) );\
	mad_opt( d, (a[6]), (b[4]) );\
	mad_opt( d, (a[7]), (b[3]) );\
	mad_opt( d, (a[8]), (b[2]) );\
	mad_opt( d, (a[9]), (b[1]) );\
\
    u0 = d & M; d >>= 26; mad_opt( c, (u0), (R0) );\
    t0 = c & M; c >>= 26; mad_opt( c, (u0), (R1) );\
\
	mad_opt( c, (a[0]), (b[1]) );\
	mad_opt( c, (a[1]), (b[0]) );\
\
	mad_opt( d, (a[2]), (b[9]) );\
	mad_opt( d, (a[3]), (b[8]) );\
	mad_opt( d, (a[4]), (b[7]) );\
	mad_opt( d, (a[5]), (b[6]) );\
	mad_opt( d, (a[6]), (b[5]) );\
	mad_opt( d, (a[7]), (b[4]) );\
	mad_opt( d, (a[8]), (b[3]) );\
	mad_opt( d, (a[9]), (b[2]) );\
\
    u1 = d & M; d >>= 26; mad_opt( c, (u1), (R0) );\
    t1 = c & M; c >>= 26; mad_opt( c, (u1), (R1) );\
\
	mad_opt( c, (a[0]), (b[2]) );\
	mad_opt( c, (a[1]), (b[1]) );\
	mad_opt( c, (a[2]), (b[0]) );\
\
	mad_opt( d, (a[3]), (b[9]) );\
	mad_opt( d, (a[4]), (b[8]) );\
	mad_opt( d, (a[5]), (b[7]) );\
	mad_opt( d, (a[6]), (b[6]) );\
	mad_opt( d, (a[7]), (b[5]) );\
	mad_opt( d, (a[8]), (b[4]) );\
	mad_opt( d, (a[9]), (b[3]) );\
\
    u2 = d & M; d >>= 26; mad_opt( c, (u2), (R0) );\
    t2 = c & M; c >>= 26; mad_opt( c, (u2), (R1) );\
\
	mad_opt( c, (a[0]), (b[3]) );\
	mad_opt( c, (a[1]), (b[2]) );\
	mad_opt( c, (a[2]), (b[1]) );\
	mad_opt( c, (a[3]), (b[0]) );\
\
	mad_opt( d, (a[4]), (b[9]) );\
	mad_opt( d, (a[5]), (b[8]) );\
	mad_opt( d, (a[6]), (b[7]) );\
	mad_opt( d, (a[7]), (b[6]) );\
	mad_opt( d, (a[8]), (b[5]) );\
	mad_opt( d, (a[9]), (b[4]) );\
\
    u3 = d & M; d >>= 26; mad_opt( c, (u3), (R0) );\
    t3 = c & M; c >>= 26; mad_opt( c, (u3), (R1) );\
\
	mad_opt( c, (a[0]), (b[4]) );\
	mad_opt( c, (a[1]), (b[3]) );\
	mad_opt( c, (a[2]), (b[2]) );\
	mad_opt( c, (a[3]), (b[1]) );\
	mad_opt( c, (a[4]), (b[0]) );\
\
	mad_opt( d, (a[5]), (b[9]) );\
	mad_opt( d, (a[6]), (b[8]) );\
	mad_opt( d, (a[7]), (b[7]) );\
	mad_opt( d, (a[8]), (b[6]) );\
	mad_opt( d, (a[9]), (b[5]) );\
\
    u4 = d & M; d >>= 26; mad_opt( c, (u4), (R0) );\
    t4 = c & M; c >>= 26; mad_opt( c, (u4), (R1) );\
\
	mad_opt( c, (a[0]), (b[5]) );\
	mad_opt( c, (a[1]), (b[4]) );\
	mad_opt( c, (a[2]), (b[3]) );\
	mad_opt( c, (a[3]), (b[2]) );\
	mad_opt( c, (a[4]), (b[1]) );\
	mad_opt( c, (a[5]), (b[0]) );\
\
	mad_opt( d, (a[6]), (b[9]) );\
	mad_opt( d, (a[7]), (b[8]) );\
	mad_opt( d, (a[8]), (b[7]) );\
	mad_opt( d, (a[9]), (b[6]) );\
\
    u5 = d & M; d >>= 26; mad_opt( c, (u5), (R0) );\
    t5 = c & M; c >>= 26; mad_opt( c, (u5), (R1) );\
\
	mad_opt( c, (a[0]), (b[6]) );\
	mad_opt( c, (a[1]), (b[5]) );\
	mad_opt( c, (a[2]), (b[4]) );\
	mad_opt( c, (a[3]), (b[3]) );\
	mad_opt( c, (a[4]), (b[2]) );\
	mad_opt( c, (a[5]), (b[1]) );\
	mad_opt( c, (a[6]), (b[0]) );\
\
	mad_opt( d, (a[7]), (b[9]) );\
	mad_opt( d, (a[8]), (b[8]) );\
	mad_opt( d, (a[9]), (b[7]) );\
\
    u6 = d & M; d >>= 26; mad_opt( c, (u6), (R0) );\
    t6 = c & M; c >>= 26; mad_opt( c, (u6), (R1) );\
\
	mad_opt( c, (a[0]), (b[7]) );\
	mad_opt( c, (a[1]), (b[6]) );\
	mad_opt( c, (a[2]), (b[5]) );\
	mad_opt( c, (a[3]), (b[4]) );\
	mad_opt( c, (a[4]), (b[3]) );\
	mad_opt( c, (a[5]), (b[2]) );\
	mad_opt( c, (a[6]), (b[1]) );\
	mad_opt( c, (a[7]), (b[0]) );\
\
	mad_opt( d, (a[8]), (b[9]) );\
	mad_opt( d, (a[9]), (b[8]) );\
\
    u7 = d & M; d >>= 26; mad_opt( c, (u7), (R0) );\
    t7 = c & M; c >>= 26; mad_opt( c, (u7), (R1) );\
\
	mad_opt( c, (a[0]), (b[8]) );\
	mad_opt( c, (a[1]), (b[7]) );\
	mad_opt( c, (a[2]), (b[6]) );\
	mad_opt( c, (a[3]), (b[5]) );\
	mad_opt( c, (a[4]), (b[4]) );\
	mad_opt( c, (a[5]), (b[3]) );\
	mad_opt( c, (a[6]), (b[2]) );\
	mad_opt( c, (a[7]), (b[1]) );\
	mad_opt( c, (a[8]), (b[0]) );\
\
	mad_opt( d, (a[9]), (b[9]) );\
    u8 = d & M; d >>= 26; mad_opt( c, (u8), (R0) );\
\
    r[3] = t3;\
    r[4] = t4;\
    r[5] = t5;\
    r[6] = t6;\
    r[7] = t7;\
    r[8] = c & M; c >>= 26; mad_opt( c, (u8), (R1) );\
\
    c   += d * R0 + t9;\
\
    r[9] = c & (M >> 4); c >>= 22; c += d * (R1 << 4);\
\
    d    = c * (R0 >> 4) + t0;\
\
    r[0] = d & M; d >>= 26;\
\
    d   += c * (R1 >> 4) + t1;\
\
    r[1] = d & M; d >>= 26;\
\
    d   += t2;\
\
    r[2] = d;\
}

#define secp256k1_fe_mul_inner_simplified1 \
{\
    uint64_t c, d;\
    uint32_t u0, u1, u2, u3, u4, u5, u6, u7, u8;\
    uint32_t t9, t1, t0, t2, t3, t4, t5, t6, t7;\
    const uint32_t M = 0x3FFFFFFUL, R0 = 0x3D10UL, R1 = 0x400UL;\
\
    d  = b[9];\
\
    t9 = d & M; d >>= 26;\
    c  = b[0];\
\
    d += 0;\
\
	volatile uint32_t carry = amd_init( d, d, d );\
    u0 = d & M; d >>= 26; mad_opt( c, u0, R0 );\
    t0 = c & M; c >>= 26; mad_opt( c, u0, R1 );\
\
    c += b[1];\
\
    d += 0;\
\
    u1 = d & M; d >>= 26; mad_opt( c, u1, R0 );\
    t1 = c & M; c >>= 26; mad_opt( c, u1, R1 );\
\
    c += b[2];\
\
    d += 0;\
\
    u2 = d & M; d >>= 26; mad_opt( c, u2, R0 );\
    t2 = c & M; c >>= 26; mad_opt( c, u2, R1 );\
\
    c += b[3];\
\
    d += 0;\
\
    u3 = d & M; d >>= 26; mad_opt( c, u3, R0 );\
    t3 = c & M; c >>= 26; mad_opt( c, u3, R1 );\
\
    c += b[4];\
\
    d += 0;\
\
    u4 = d & M; d >>= 26; mad_opt( c, u4, R0 );\
    t4 = c & M; c >>= 26; mad_opt( c, u4, R1 );\
\
    c += b[5];\
\
    d += 0;\
\
    u5 = d & M; d >>= 26; mad_opt( c, u5, R0 );\
    t5 = c & M; c >>= 26; mad_opt( c, u5, R1 );\
\
    c += b[6];\
\
    d += 0;\
\
    u6 = d & M; d >>= 26; mad_opt( c, u6, R0 );\
    t6 = c & M; c >>= 26; mad_opt( c, u6, R1 );\
\
    c += b[7];\
\
    d += 0;\
\
    u7 = d & M; d >>= 26; mad_opt( c, u7, R0 );\
    t7 = c & M; c >>= 26; mad_opt( c, u7, R1 );\
\
    c += b[8];\
\
    d += 0;\
    u8 = d & M; d >>= 26; mad_opt( c, u8, R0 );\
\
    r[3] = t3;\
    r[4] = t4;\
    r[5] = t5;\
    r[6] = t6;\
    r[7] = t7;\
    r[8] = c & M; c >>= 26; mad_opt( c, u8, R1 );\
\
    c   += d * R0 + t9;\
\
    r[9] = c & (M >> 4); c >>= 22; c += d * (R1 << 4);\
\
    d    = c * (R0 >> 4) + t0;\
\
    r[0] = d & M; d >>= 26;\
\
    d   += c * (R1 >> 4) + t1;\
\
    r[1] = d & M; d >>= 26;\
\
    d   += t2;\
\
    r[2] = d;\
}

#define secp256k1_fe_add( __r, __a ) \
{\
	__r[0] += __a[0];\
	__r[1] += __a[1];\
	__r[2] += __a[2];\
	__r[3] += __a[3];\
	__r[4] += __a[4];\
	__r[5] += __a[5];\
	__r[6] += __a[6];\
	__r[7] += __a[7];\
	__r[8] += __a[8];\
	__r[9] += __a[9];\
}

#define secp256k1_fe_negate( __r, __a, __m ) \
{\
	__r[0] = 0x3FFFC2FUL * 2 * (__m + 1) - __a[0];\
	__r[1] = 0x3FFFFBFUL * 2 * (__m + 1) - __a[1];\
	__r[2] = 0x3FFFFFFUL * 2 * (__m + 1) - __a[2];\
	__r[3] = 0x3FFFFFFUL * 2 * (__m + 1) - __a[3];\
	__r[4] = 0x3FFFFFFUL * 2 * (__m + 1) - __a[4];\
	__r[5] = 0x3FFFFFFUL * 2 * (__m + 1) - __a[5];\
	__r[6] = 0x3FFFFFFUL * 2 * (__m + 1) - __a[6];\
	__r[7] = 0x3FFFFFFUL * 2 * (__m + 1) - __a[7];\
	__r[8] = 0x3FFFFFFUL * 2 * (__m + 1) - __a[8];\
	__r[9] = 0x03FFFFFUL * 2 * (__m + 1) - __a[9];\
}

SECP256K1_INLINE uint32_t secp256k1_fe_normalizes_to_zero( uint32_t *r )
{
    uint32_t t0 = r[0], t1 = r[1], t2 = r[2], t3 = r[3], t4 = r[4],
             t5 = r[5], t6 = r[6], t7 = r[7], t8 = r[8], t9 = r[9];

    /* z0 tracks a possible raw value of 0, z1 tracks a possible raw value of P */
    uint32_t z0, z1;

    /* Reduce t9 at the start so there will be at most a single carry from the first pass */
    uint32_t x = t9 >> 22; t9 &= 0x03FFFFFUL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x3D1UL; t1 += (x << 6);
    t1 += (t0 >> 26); t0 &= 0x3FFFFFFUL; z0  = t0; z1  = t0 ^ 0x3D0UL;
    t2 += (t1 >> 26); t1 &= 0x3FFFFFFUL; z0 |= t1; z1 &= t1 ^ 0x40UL;
    t3 += (t2 >> 26); t2 &= 0x3FFFFFFUL; z0 |= t2; z1 &= t2;
    t4 += (t3 >> 26); t3 &= 0x3FFFFFFUL; z0 |= t3; z1 &= t3;
    t5 += (t4 >> 26); t4 &= 0x3FFFFFFUL; z0 |= t4; z1 &= t4;
    t6 += (t5 >> 26); t5 &= 0x3FFFFFFUL; z0 |= t5; z1 &= t5;
    t7 += (t6 >> 26); t6 &= 0x3FFFFFFUL; z0 |= t6; z1 &= t6;
    t8 += (t7 >> 26); t7 &= 0x3FFFFFFUL; z0 |= t7; z1 &= t7;
    t9 += (t8 >> 26); t8 &= 0x3FFFFFFUL; z0 |= t8; z1 &= t8;
                                         z0 |= t9; z1 &= t9 ^ 0x3C00000UL;

    return (z0 == 0) | (z1 == 0x3FFFFFFUL);
}

#define secp256k1_fe_mul_int( __r, __a ) \
{\
	__r[0] *= __a;\
	__r[1] *= __a;\
	__r[2] *= __a;\
	__r[3] *= __a;\
	__r[4] *= __a;\
	__r[5] *= __a;\
	__r[6] *= __a;\
	__r[7] *= __a;\
	__r[8] *= __a;\
	__r[9] *= __a;\
}

#define secp256k1_fe_cmov( __r, __a ) \
{\
	__r[0] = __a[0];\
	__r[1] = __a[1];\
	__r[2] = __a[2];\
	__r[3] = __a[3];\
	__r[4] = __a[4];\
	__r[5] = __a[5];\
	__r[6] = __a[6];\
	__r[7] = __a[7];\
	__r[8] = __a[8];\
	__r[9] = __a[9];\
}

void secp256k1_fe_mul( uint32_t *r, uint32_t *a, uint32_t * SECP256K1_RESTRICT b ) secp256k1_fe_mul_inner
void secp256k1_fe_mul_lgl( uint32_t *r, __global uint32_t *a, uint32_t * SECP256K1_RESTRICT b ) secp256k1_fe_mul_inner
void secp256k1_fe_mul_ggl( __global uint32_t *r, __global uint32_t *a, uint32_t * SECP256K1_RESTRICT b ) secp256k1_fe_mul_inner
void secp256k1_fe_mul_simplified1( uint32_t *r, uint32_t * SECP256K1_RESTRICT b ) secp256k1_fe_mul_inner_simplified1
void secp256k1_fe_sqr( uint32_t *r, uint32_t *a ) secp256k1_fe_sqr_inner
void secp256k1_fe_sqr_lg( uint32_t *r, __global uint32_t *a ) secp256k1_fe_sqr_inner

typedef struct {
    int32_t v[9];
} secp256k1_modinv32_signed30;

typedef struct {
    /* The modulus in signed30 notation, must be odd and in [3, 2^256]. */
    secp256k1_modinv32_signed30 modulus;

    /* modulus^{-1} mod 2^30 */
    uint32_t modulus_inv30;
} secp256k1_modinv32_modinfo;

SECP256K1_INLINE void secp256k1_fe_to_signed30(secp256k1_modinv32_signed30 *r, const uint32_t *a) {
    const uint32_t M30 = UINT32_MAX >> 2;
    const uint64_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4],
                   a5 = a[5], a6 = a[6], a7 = a[7], a8 = a[8], a9 = a[9];

    r->v[0] = (a0       | a1 << 26) & M30;
    r->v[1] = (a1 >>  4 | a2 << 22) & M30;
    r->v[2] = (a2 >>  8 | a3 << 18) & M30;
    r->v[3] = (a3 >> 12 | a4 << 14) & M30;
    r->v[4] = (a4 >> 16 | a5 << 10) & M30;
    r->v[5] = (a5 >> 20 | a6 <<  6) & M30;
    r->v[6] = (a6 >> 24 | a7 <<  2
                        | a8 << 28) & M30;
    r->v[7] = (a8 >>  2 | a9 << 24) & M30;
    r->v[8] =  a9 >>  6;
}

typedef struct {
    int32_t u, v, q, r;
} secp256k1_modinv32_trans2x2;

SECP256K1_INLINE void secp256k1_modinv32_normalize_30(secp256k1_modinv32_signed30 *r, int32_t sign, const secp256k1_modinv32_modinfo *modinfo) {
    const int32_t M30 = (int32_t)(UINT32_MAX >> 2);
    int32_t r0 = r->v[0], r1 = r->v[1], r2 = r->v[2], r3 = r->v[3], r4 = r->v[4],
            r5 = r->v[5], r6 = r->v[6], r7 = r->v[7], r8 = r->v[8];
    int32_t cond_add, cond_negate;


    /* In a first step, add the modulus if the input is negative, and then negate if requested.
     * This brings r from range (-2*modulus,modulus) to range (-modulus,modulus). As all input
     * limbs are in range (-2^30,2^30), this cannot overflow an int32_t. Note that the right
     * shifts below are signed sign-extending shifts (see assumptions.h for tests that that is
     * indeed the behavior of the right shift operator). */
    cond_add = r8 >> 31;
    r0 += modinfo->modulus.v[0] & cond_add;
    r1 += modinfo->modulus.v[1] & cond_add;
    r2 += modinfo->modulus.v[2] & cond_add;
    r3 += modinfo->modulus.v[3] & cond_add;
    r4 += modinfo->modulus.v[4] & cond_add;
    r5 += modinfo->modulus.v[5] & cond_add;
    r6 += modinfo->modulus.v[6] & cond_add;
    r7 += modinfo->modulus.v[7] & cond_add;
    r8 += modinfo->modulus.v[8] & cond_add;
    cond_negate = sign >> 31;
    r0 = (r0 ^ cond_negate) - cond_negate;
    r1 = (r1 ^ cond_negate) - cond_negate;
    r2 = (r2 ^ cond_negate) - cond_negate;
    r3 = (r3 ^ cond_negate) - cond_negate;
    r4 = (r4 ^ cond_negate) - cond_negate;
    r5 = (r5 ^ cond_negate) - cond_negate;
    r6 = (r6 ^ cond_negate) - cond_negate;
    r7 = (r7 ^ cond_negate) - cond_negate;
    r8 = (r8 ^ cond_negate) - cond_negate;
    /* Propagate the top bits, to bring limbs back to range (-2^30,2^30). */
    r1 += r0 >> 30; r0 &= M30;
    r2 += r1 >> 30; r1 &= M30;
    r3 += r2 >> 30; r2 &= M30;
    r4 += r3 >> 30; r3 &= M30;
    r5 += r4 >> 30; r4 &= M30;
    r6 += r5 >> 30; r5 &= M30;
    r7 += r6 >> 30; r6 &= M30;
    r8 += r7 >> 30; r7 &= M30;

    /* In a second step add the modulus again if the result is still negative, bringing r to range
     * [0,modulus). */
    cond_add = r8 >> 31;
    r0 += modinfo->modulus.v[0] & cond_add;
    r1 += modinfo->modulus.v[1] & cond_add;
    r2 += modinfo->modulus.v[2] & cond_add;
    r3 += modinfo->modulus.v[3] & cond_add;
    r4 += modinfo->modulus.v[4] & cond_add;
    r5 += modinfo->modulus.v[5] & cond_add;
    r6 += modinfo->modulus.v[6] & cond_add;
    r7 += modinfo->modulus.v[7] & cond_add;
    r8 += modinfo->modulus.v[8] & cond_add;
    /* And propagate again. */
    r1 += r0 >> 30; r0 &= M30;
    r2 += r1 >> 30; r1 &= M30;
    r3 += r2 >> 30; r2 &= M30;
    r4 += r3 >> 30; r3 &= M30;
    r5 += r4 >> 30; r4 &= M30;
    r6 += r5 >> 30; r5 &= M30;
    r7 += r6 >> 30; r6 &= M30;
    r8 += r7 >> 30; r7 &= M30;

    r->v[0] = r0;
    r->v[1] = r1;
    r->v[2] = r2;
    r->v[3] = r3;
    r->v[4] = r4;
    r->v[5] = r5;
    r->v[6] = r6;
    r->v[7] = r7;
    r->v[8] = r8;
}

SECP256K1_INLINE int32_t secp256k1_modinv32_divsteps_30(int32_t zeta, uint32_t f0, uint32_t g0, secp256k1_modinv32_trans2x2 *t) {
    uint32_t u = 1, v = 0, q = 0, r = 1;
    uint32_t c1, c2, f = f0, g = g0, x, y, z;
    int i;

    for (i = 0; i < 30; ++i) {
        /* Compute conditional masks for (zeta < 0) and for (g & 1). */
        c1 = zeta >> 31;
        c2 = -(g & 1);
        /* Compute x,y,z, conditionally negated versions of f,u,v. */
        x = (f ^ c1) - c1;
        y = (u ^ c1) - c1;
        z = (v ^ c1) - c1;
        /* Conditionally add x,y,z to g,q,r. */
        g += x & c2;
        q += y & c2;
        r += z & c2;
        /* In what follows, c1 is a condition mask for (zeta < 0) and (g & 1). */
        c1 &= c2;
        /* Conditionally change zeta into -zeta-2 or zeta-1. */
        zeta = (zeta ^ c1) - 1;
        /* Conditionally add g,q,r to f,u,v. */
        f += g & c1;
        u += q & c1;
        v += r & c1;
        /* Shifts */
        g >>= 1;
        u <<= 1;
        v <<= 1;
    }
    /* Return data in t and return value. */
    t->u = (int32_t)u;
    t->v = (int32_t)v;
    t->q = (int32_t)q;
    t->r = (int32_t)r;

    return zeta;
}

SECP256K1_INLINE void secp256k1_modinv32_update_de_30(secp256k1_modinv32_signed30 *d, secp256k1_modinv32_signed30 *e, const secp256k1_modinv32_trans2x2 *t, const secp256k1_modinv32_modinfo* modinfo) {
    const int32_t M30 = (int32_t)(UINT32_MAX >> 2);
    const int32_t u = t->u, v = t->v, q = t->q, r = t->r;
	volatile int32_t carry = amd_init( u, u, u );\
    int32_t di, ei, md, me, sd, se;
    int64_t cd = 0, ce = 0;
    int i;

    /* [md,me] start as zero; plus [u,q] if d is negative; plus [v,r] if e is negative. */
    sd = d->v[8] >> 31;
    se = e->v[8] >> 31;
    md = (u & sd) + (v & se);
    me = (q & sd) + (r & se);
    /* Begin computing t*[d,e]. */
    di = d->v[0];
    ei = e->v[0];
	madi_opt( cd, u, di );
	madi_opt( cd, v, ei );
	madi_opt( ce, q, di );
	madi_opt( ce, r, ei );
    /* Correct md,me so that t*[d,e]+modulus*[md,me] has 30 zero bottom bits. */
    md -= (modinfo->modulus_inv30 * (uint32_t)cd + md) & M30;
    me -= (modinfo->modulus_inv30 * (uint32_t)ce + me) & M30;
    /* Update the beginning of computation for t*[d,e]+modulus*[md,me] now md,me are known. */
	madi_opt( cd, modinfo->modulus.v[0], md );
	madi_opt( ce, modinfo->modulus.v[0], me );
	cd >>= 30;
	ce >>= 30;
    /* Now iteratively compute limb i=1..8 of t*[d,e]+modulus*[md,me], and store them in output
     * limb i-1 (shifting down by 30 bits). */
	#pragma unroll
    for (i = 1; i < 9; ++i) {
        di = d->v[i];
        ei = e->v[i];
		madi_opt( cd, u, di );
		madi_opt( cd, v, ei );
		madi_opt( ce, q, di );
		madi_opt( ce, r, ei );
		madi_opt( cd, modinfo->modulus.v[i], md );
		madi_opt( ce, modinfo->modulus.v[i], me );
        d->v[i - 1] = (int32_t)cd & M30; cd >>= 30;
        e->v[i - 1] = (int32_t)ce & M30; ce >>= 30;
    }
    /* What remains is limb 9 of t*[d,e]+modulus*[md,me]; store it as output limb 8. */
    d->v[8] = (int32_t)cd;
    e->v[8] = (int32_t)ce;
}

SECP256K1_INLINE void secp256k1_modinv32_update_fg_30(secp256k1_modinv32_signed30 *f, secp256k1_modinv32_signed30 *g, const secp256k1_modinv32_trans2x2 *t) {
    const int32_t M30 = (int32_t)(UINT32_MAX >> 2);
    const int32_t u = t->u, v = t->v, q = t->q, r = t->r;
	volatile int32_t carry = amd_init( u, u, u );\
    int32_t fi, gi;
    int64_t cf = 0, cg = 0;
    int i;
    /* Start computing t*[f,g]. */
    fi = f->v[0];
    gi = g->v[0];
	madi_opt( cf, u, fi );
	madi_opt( cf, v, gi );
	madi_opt( cg, q, fi );
	madi_opt( cg, r, gi );
    cf >>= 30;
	cg >>= 30;
    /* Now iteratively compute limb i=1..8 of t*[f,g], and store them in output limb i-1 (shifting
     * down by 30 bits). */
	#pragma unroll
    for (i = 1; i < 9; ++i) {
        fi = f->v[i];
        gi = g->v[i];
		madi_opt( cf, u, fi );
		madi_opt( cf, v, gi );
		madi_opt( cg, q, fi );
		madi_opt( cg, r, gi );
        f->v[i - 1] = (int32_t)cf & M30; cf >>= 30;
        g->v[i - 1] = (int32_t)cg & M30; cg >>= 30;
    }
    /* What remains is limb 9 of t*[f,g]; store it as output limb 8. */
    f->v[8] = (int32_t)cf;
    g->v[8] = (int32_t)cg;
}

SECP256K1_INLINE void secp256k1_modinv32(secp256k1_modinv32_signed30 *x, const secp256k1_modinv32_modinfo *modinfo) {
    secp256k1_modinv32_signed30 d = {{0}};
    secp256k1_modinv32_signed30 e = {{1}};
    secp256k1_modinv32_signed30 f = modinfo->modulus;
    secp256k1_modinv32_signed30 g = *x;
    int i;
    int32_t zeta = -1; /* zeta = -(delta+1/2); delta is initially 1/2. */

	#pragma unroll 2
    for (i = 0; i < 20; ++i) {
        secp256k1_modinv32_trans2x2 t;
        zeta = secp256k1_modinv32_divsteps_30(zeta, f.v[0], g.v[0], &t);
        secp256k1_modinv32_update_de_30(&d, &e, &t, modinfo);
        secp256k1_modinv32_update_fg_30(&f, &g, &t);
    }

    secp256k1_modinv32_normalize_30(&d, f.v[8], modinfo);
    *x = d;
}

SECP256K1_INLINE void secp256k1_fe_from_signed30(uint32_t *r, const secp256k1_modinv32_signed30 *a) {
    const uint32_t M26 = UINT32_MAX >> 6;
    const uint32_t a0 = a->v[0], a1 = a->v[1], a2 = a->v[2], a3 = a->v[3], a4 = a->v[4],
                   a5 = a->v[5], a6 = a->v[6], a7 = a->v[7], a8 = a->v[8];

    r[0] =  a0                   & M26;
    r[1] = (a0 >> 26 | a1 <<  4) & M26;
    r[2] = (a1 >> 22 | a2 <<  8) & M26;
    r[3] = (a2 >> 18 | a3 << 12) & M26;
    r[4] = (a3 >> 14 | a4 << 16) & M26;
    r[5] = (a4 >> 10 | a5 << 20) & M26;
    r[6] = (a5 >>  6 | a6 << 24) & M26;
    r[7] = (a6 >>  2           ) & M26;
    r[8] = (a6 >> 28 | a7 <<  2) & M26;
    r[9] = (a7 >> 24 | a8 <<  6);
}

SECP256K1_INLINE void secp256k1_fe_from_signed30_global(__global uint32_t *r, const secp256k1_modinv32_signed30 *a) {
    const uint32_t M26 = UINT32_MAX >> 6;
    const uint32_t a0 = a->v[0], a1 = a->v[1], a2 = a->v[2], a3 = a->v[3], a4 = a->v[4],
                   a5 = a->v[5], a6 = a->v[6], a7 = a->v[7], a8 = a->v[8];

    r[0] =  a0                   & M26;
    r[1] = (a0 >> 26 | a1 <<  4) & M26;
    r[2] = (a1 >> 22 | a2 <<  8) & M26;
    r[3] = (a2 >> 18 | a3 << 12) & M26;
    r[4] = (a3 >> 14 | a4 << 16) & M26;
    r[5] = (a4 >> 10 | a5 << 20) & M26;
    r[6] = (a5 >>  6 | a6 << 24) & M26;
    r[7] = (a6 >>  2           ) & M26;
    r[8] = (a6 >> 28 | a7 <<  2) & M26;
    r[9] = (a7 >> 24 | a8 <<  6);
}

SECP256K1_INLINE void secp256k1_fe_inv( uint32_t *r, uint32_t *a )
{
const secp256k1_modinv32_modinfo secp256k1_const_modinfo_fe = {
    {{-0x3D1, -4, 0, 0, 0, 0, 0, 0, 65536}},
    0x2DDACACFL
};

    uint32_t tmp[10];
    secp256k1_modinv32_signed30 s;

    secp256k1_fe_cmov( tmp, a );
    secp256k1_fe_normalize( tmp );
    secp256k1_fe_to_signed30(&s, tmp);
    secp256k1_modinv32(&s, &secp256k1_const_modinfo_fe);
    secp256k1_fe_from_signed30(r, &s);
}

SECP256K1_INLINE void secp256k1_fe_inv_global( __global uint32_t *r, __global uint32_t *a )
{
const secp256k1_modinv32_modinfo secp256k1_const_modinfo_fe = {
    {{-0x3D1, -4, 0, 0, 0, 0, 0, 0, 65536}},
    0x2DDACACFL
};

    uint32_t tmp[10];
    secp256k1_modinv32_signed30 s;

    secp256k1_fe_cmov( tmp, a );
    secp256k1_fe_normalize( tmp );
    secp256k1_fe_to_signed30(&s, tmp);
    secp256k1_modinv32(&s, &secp256k1_const_modinfo_fe);
    secp256k1_fe_from_signed30_global(r, &s);
}

SECP256K1_INLINE void secp256k1_ge_set_gej(secp256k1_ge *r, secp256k1_gej *a)
{
	uint32_t z2[10], z3[10];
	secp256k1_fe_inv( a->z, a->z);
	secp256k1_fe_sqr( z2, a->z );
	secp256k1_fe_mul( z3, a->z, z2 );
	secp256k1_fe_mul( a->x, a->x, z2 );
	secp256k1_fe_mul( a->y, a->y, z3 );
	secp256k1_fe_set_int( a->z, 1);
	secp256k1_fe_cmov( r->x, a->x );
	secp256k1_fe_cmov( r->y, a->y );
}

SECP256K1_INLINE void secp256k1_ge_set_gej_global(secp256k1_ge *r, __global secp256k1_gej *a)
{
	uint32_t z2[10], z3[10];
	secp256k1_fe_inv_global( a->z, a->z);
	secp256k1_fe_sqr_lg( z2, a->z );
	secp256k1_fe_mul_lgl( z3, a->z, z2 );
	secp256k1_fe_mul_ggl( a->x, a->x, z2 );
	secp256k1_fe_mul_ggl( a->y, a->y, z3 );
	secp256k1_fe_set_int( a->z, 1);
	secp256k1_fe_cmov( r->x, a->x );
	secp256k1_fe_cmov( r->y, a->y );
}

#define secp256k1_fe_to_storage( r, a ) \
{\
	r[0] = a[0] | a[1] << 26;\
	r[1] = a[1] >> 6 | a[2] << 20;\
	r[2] = a[2] >> 12 | a[3] << 14;\
	r[3] = a[3] >> 18 | a[4] << 8;\
	r[4] = a[4] >> 24 | a[5] << 2 | a[6] << 28;\
	r[5] = a[6] >> 4 | a[7] << 22;\
	r[6] = a[7] >> 10 | a[8] << 16;\
	r[7] = a[8] >> 16 | a[9] << 10;\
}

SECP256K1_INLINE void secp256k1_fe_get_b32( __global unsigned char *r, uint32_t *a )
{
	r[0] = (a[9] >> 14) & 0xff;
	r[1] = (a[9] >> 6) & 0xff;
	r[2] = ((a[9] & 0x3F) << 2) | ((a[8] >> 24) & 0x3);
	r[3] = (a[8] >> 16) & 0xff;
	r[4] = (a[8] >> 8) & 0xff;
	r[5] = a[8] & 0xff;
	r[6] = (a[7] >> 18) & 0xff;
	r[7] = (a[7] >> 10) & 0xff;
	r[8] = (a[7] >> 2) & 0xff;
	r[9] = ((a[7] & 0x3) << 6) | ((a[6] >> 20) & 0x3f);
	r[10] = (a[6] >> 12) & 0xff;
	r[11] = (a[6] >> 4) & 0xff;
	r[12] = ((a[6] & 0xf) << 4) | ((a[5] >> 22) & 0xf);
	r[13] = (a[5] >> 14) & 0xff;
	r[14] = (a[5] >> 6) & 0xff;
	r[15] = ((a[5] & 0x3f) << 2) | ((a[4] >> 24) & 0x3);
	r[16] = (a[4] >> 16) & 0xff;
	r[17] = (a[4] >> 8) & 0xff;
	r[18] = a[4] & 0xff;
	r[19] = (a[3] >> 18) & 0xff;
	r[20] = (a[3] >> 10) & 0xff;
	r[21] = (a[3] >> 2) & 0xff;
	r[22] = ((a[3] & 0x3) << 6) | ((a[2] >> 20) & 0x3f);
	r[23] = (a[2] >> 12) & 0xff;
	r[24] = (a[2] >> 4) & 0xff;
	r[25] = ((a[2] & 0xf) << 4) | ((a[1] >> 22) & 0xf);
	r[26] = (a[1] >> 14) & 0xff;
	r[27] = (a[1] >> 6) & 0xff;
	r[28] = ((a[1] & 0x3f) << 2) | ((a[0] >> 24) & 0x3);
	r[29] = (a[0] >> 16) & 0xff;
	r[30] = (a[0] >> 8) & 0xff;
	r[31] = a[0] & 0xff;
}

SECP256K1_INLINE void secp256k1_fe_get_b32_local( unsigned char *r, uint32_t *a )
{
	r[0] = (a[9] >> 14) & 0xff;
	r[1] = (a[9] >> 6) & 0xff;
	r[2] = ((a[9] & 0x3F) << 2) | ((a[8] >> 24) & 0x3);
	r[3] = (a[8] >> 16) & 0xff;
	r[4] = (a[8] >> 8) & 0xff;
	r[5] = a[8] & 0xff;
	r[6] = (a[7] >> 18) & 0xff;
	r[7] = (a[7] >> 10) & 0xff;
	r[8] = (a[7] >> 2) & 0xff;
	r[9] = ((a[7] & 0x3) << 6) | ((a[6] >> 20) & 0x3f);
	r[10] = (a[6] >> 12) & 0xff;
	r[11] = (a[6] >> 4) & 0xff;
	r[12] = ((a[6] & 0xf) << 4) | ((a[5] >> 22) & 0xf);
	r[13] = (a[5] >> 14) & 0xff;
	r[14] = (a[5] >> 6) & 0xff;
	r[15] = ((a[5] & 0x3f) << 2) | ((a[4] >> 24) & 0x3);
	r[16] = (a[4] >> 16) & 0xff;
	r[17] = (a[4] >> 8) & 0xff;
	r[18] = a[4] & 0xff;
	r[19] = (a[3] >> 18) & 0xff;
	r[20] = (a[3] >> 10) & 0xff;
	r[21] = (a[3] >> 2) & 0xff;
	r[22] = ((a[3] & 0x3) << 6) | ((a[2] >> 20) & 0x3f);
	r[23] = (a[2] >> 12) & 0xff;
	r[24] = (a[2] >> 4) & 0xff;
	r[25] = ((a[2] & 0xf) << 4) | ((a[1] >> 22) & 0xf);
	r[26] = (a[1] >> 14) & 0xff;
	r[27] = (a[1] >> 6) & 0xff;
	r[28] = ((a[1] & 0x3f) << 2) | ((a[0] >> 24) & 0x3);
	r[29] = (a[0] >> 16) & 0xff;
	r[30] = (a[0] >> 8) & 0xff;
	r[31] = a[0] & 0xff;
}

int secp256k1_fe_normalizes_to_zero_var(uint32_t *r) {
    uint32_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9;
    uint32_t z0, z1;
    uint32_t x;

    t0 = r[0];
    t9 = r[9];

    /* Reduce t9 at the start so there will be at most a single carry from the first pass */
    x = t9 >> 22;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x3D1UL;

    /* z0 tracks a possible raw value of 0, z1 tracks a possible raw value of P */
    z0 = t0 & 0x3FFFFFFUL;
    z1 = z0 ^ 0x3D0UL;

    /* Fast return path should catch the majority of cases */
    if ((z0 != 0UL) && (z1 != 0x3FFFFFFUL)) {
        return 0;
    }

    t1 = r[1];
    t2 = r[2];
    t3 = r[3];
    t4 = r[4];
    t5 = r[5];
    t6 = r[6];
    t7 = r[7];
    t8 = r[8];

    t9 &= 0x03FFFFFUL;
    t1 += (x << 6);

    t1 += (t0 >> 26);
    t2 += (t1 >> 26); t1 &= 0x3FFFFFFUL; z0 |= t1; z1 &= t1 ^ 0x40UL;
    t3 += (t2 >> 26); t2 &= 0x3FFFFFFUL; z0 |= t2; z1 &= t2;
    t4 += (t3 >> 26); t3 &= 0x3FFFFFFUL; z0 |= t3; z1 &= t3;
    t5 += (t4 >> 26); t4 &= 0x3FFFFFFUL; z0 |= t4; z1 &= t4;
    t6 += (t5 >> 26); t5 &= 0x3FFFFFFUL; z0 |= t5; z1 &= t5;
    t7 += (t6 >> 26); t6 &= 0x3FFFFFFUL; z0 |= t6; z1 &= t6;
    t8 += (t7 >> 26); t7 &= 0x3FFFFFFUL; z0 |= t7; z1 &= t7;
    t9 += (t8 >> 26); t8 &= 0x3FFFFFFUL; z0 |= t8; z1 &= t8;
                                         z0 |= t9; z1 &= t9 ^ 0x3C00000UL;

    return (z0 == 0) | (z1 == 0x3FFFFFFUL);
}


SECP256K1_INLINE int secp256k1_fe_equal_var(const uint32_t *a, uint32_t *b) {
    uint32_t na[10];
    secp256k1_fe_negate(na, a, 1);
    secp256k1_fe_add(na, b);
    return secp256k1_fe_normalizes_to_zero_var(na);
}

SECP256K1_INLINE int secp256k1_fe_sqrt_var(uint32_t *r, uint32_t *a) {
    /** Given that p is congruent to 3 mod 4, we can compute the square root of
     *  a mod p as the (p+1)/4'th power of a.
     *
     *  As (p+1)/4 is an even number, it will have the same result for a and for
     *  (-a). Only one of these two numbers actually has a square root however,
     *  so we test at the end by squaring and comparing to the input.
     *  Also because (p+1)/4 is an even number, the computed square root is
     *  itself always a square (a ** ((p+1)/4) is the square of a ** ((p+1)/8)).
     */
    uint32_t x2[10], x3[10], x6[10], x9[10], x11[10], x22[10], x44[10], x88[10], x176[10], x220[10], x223[10], t1[10];
    int j;

    /** The binary representation of (p + 1)/4 has 3 blocks of 1s, with lengths in
     *  { 2, 22, 223 }. Use an addition chain to calculate 2^n - 1 for each block:
     *  1, [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]
     */

    secp256k1_fe_sqr(x2, a);
    secp256k1_fe_mul(x2, x2, a);

    secp256k1_fe_sqr(x3, x2);
    secp256k1_fe_mul(x3, x3, a);

    secp256k1_fe_cmov( x6, x3 );
    for (j=0; j<3; j++) {
        secp256k1_fe_sqr(x6, x6);
    }
    secp256k1_fe_mul(x6, x6, x3);

    secp256k1_fe_cmov( x9, x6 );
    for (j=0; j<3; j++) {
        secp256k1_fe_sqr(x9, x9);
    }
    secp256k1_fe_mul(x9, x9, x3);

    secp256k1_fe_cmov( x11, x9 );
    for (j=0; j<2; j++) {
        secp256k1_fe_sqr(x11, x11);
    }
    secp256k1_fe_mul(x11, x11, x2);

    secp256k1_fe_cmov( x22, x11 );
    for (j=0; j<11; j++) {
        secp256k1_fe_sqr(x22, x22);
    }
    secp256k1_fe_mul(x22, x22, x11);

    secp256k1_fe_cmov( x44, x22 );
    for (j=0; j<22; j++) {
        secp256k1_fe_sqr(x44, x44);
    }
    secp256k1_fe_mul(x44, x44, x22);

    secp256k1_fe_cmov( x88, x44 );
    for (j=0; j<44; j++) {
        secp256k1_fe_sqr(x88, x88);
    }
    secp256k1_fe_mul(x88, x88, x44);

    secp256k1_fe_cmov( x176, x88 );
    for (j=0; j<88; j++) {
        secp256k1_fe_sqr(x176, x176);
    }
    secp256k1_fe_mul(x176, x176, x88);

    secp256k1_fe_cmov( x220, x176 );
    for (j=0; j<44; j++) {
        secp256k1_fe_sqr(x220, x220);
    }
    secp256k1_fe_mul(x220, x220, x44);

    secp256k1_fe_cmov( x223, x220 );
    for (j=0; j<3; j++) {
        secp256k1_fe_sqr(x223, x223);
    }
    secp256k1_fe_mul(x223, x223, x3);

    /* The final result is then assembled using a sliding window over the blocks. */

    secp256k1_fe_cmov( t1, x223 );
    for (j=0; j<23; j++) {
        secp256k1_fe_sqr(t1, t1);
    }
    secp256k1_fe_mul(t1, t1, x22);
    for (j=0; j<6; j++) {
        secp256k1_fe_sqr(t1, t1);
    }
    secp256k1_fe_mul(t1, t1, x2);
    secp256k1_fe_sqr(t1, t1);
    secp256k1_fe_sqr(r, t1);

    /* Check that a square root was actually calculated */

    secp256k1_fe_sqr(t1, r);
    return secp256k1_fe_equal_var(t1, a);
}

// ECMULT_BIG

SECP256K1_INLINE void secp256k1_gej_set_ge( secp256k1_gej *r, secp256k1_ge *a )
{
	secp256k1_fe_cmov(r->x, a->x);
	secp256k1_fe_cmov(r->y, a->y);
	secp256k1_fe_set_int(r->z, 1);
}

#ifdef OPENCL
SECP256K1_INLINE void secp256k1_gej_add_ge_var( secp256k1_gej *r, secp256k1_gej *a, secp256k1_ge *b )
{
	uint32_t z12[10], u1[10], u2[10], s1[10], s2[10], h[10], i[10], i2[10], h2[10], h3[10], t[10];

	secp256k1_fe_sqr( z12, a->z );
	secp256k1_fe_cmov( u1, a->x );
	secp256k1_fe_normalize_weak( u1 );
	secp256k1_fe_mul( u2, b->x, z12 );
	secp256k1_fe_cmov( s1, a->y );
	secp256k1_fe_normalize_weak( s1 );
	secp256k1_fe_mul( s2, b->y, z12 );
	secp256k1_fe_mul( s2, s2, a->z );
	secp256k1_fe_negate( h, u1, 1 );
	secp256k1_fe_add( h, u2 );
	secp256k1_fe_negate( i, s1, 1 );
	secp256k1_fe_add( i, s2 );

	secp256k1_fe_sqr( i2, i );
	secp256k1_fe_sqr( h2, h );
	secp256k1_fe_mul( h3, h, h2 );

	secp256k1_fe_mul( r->z, a->z, h );
	secp256k1_fe_mul( t, u1, h2 );
	secp256k1_fe_cmov( r->x, t );
	secp256k1_fe_mul_int( r->x, 2 );
	secp256k1_fe_add( r->x, h3 );
	secp256k1_fe_negate( r->x, r->x, 3 );
	secp256k1_fe_add( r->x, i2 );
	secp256k1_fe_negate( r->y, r->x, 5 );
	secp256k1_fe_add( r->y, t );
	secp256k1_fe_mul( r->y, r->y, i );
	secp256k1_fe_mul( h3, h3, s1 );
	secp256k1_fe_negate( h3, h3, 1 );
	secp256k1_fe_add( r->y, h3 );
}
#else
SECP256K1_INLINE void secp256k1_gej_double_var( secp256k1_gej *r, secp256k1_gej *a )
{
	uint32_t t1[10],t2[10],t3[10],t4[10];

	secp256k1_fe_mul(r->z, a->z, a->y);
	secp256k1_fe_mul_int(r->z, 2);
	secp256k1_fe_sqr(t1, a->x);
	secp256k1_fe_mul_int(t1, 3);
	secp256k1_fe_sqr(t2, t1);
	secp256k1_fe_sqr(t3, a->y);
	secp256k1_fe_mul_int(t3, 2);
	secp256k1_fe_sqr(t4, t3);
	secp256k1_fe_mul_int(t4, 2);
	secp256k1_fe_mul(t3, t3, a->x);
	secp256k1_fe_cmov(r->x, t3);
	secp256k1_fe_mul_int(r->x, 4);
	secp256k1_fe_negate(r->x, r->x, 4);
	secp256k1_fe_add(r->x, t2);
	secp256k1_fe_negate(t2, t2, 1);
	secp256k1_fe_mul_int(t3, 6);
	secp256k1_fe_add(t3, t2);
	secp256k1_fe_mul(r->y, t1, t3);
	secp256k1_fe_negate(t2, t4, 2);
	secp256k1_fe_add(r->y, t2);
}

SECP256K1_INLINE void secp256k1_gej_double_var( __global secp256k1_gej *r, __global secp256k1_gej *a, __global uint32_t *rzr )
{
	uint32_t t1[10],t2[10],t3[10],t4[10];

	if ( rzr != NULL )
	{
		secp256k1_fe_cmov( rzr, a->y );
		secp256k1_fe_normalize_weak(rzr);
		secp256k1_fe_mul_int(rzr, 2);
	}

	secp256k1_fe_mul(r->z, a->z, a->y);
	secp256k1_fe_mul_int(r->z, 2);
	secp256k1_fe_sqr(t1, a->x);
	secp256k1_fe_mul_int(t1, 3);
	secp256k1_fe_sqr(t2, t1);
	secp256k1_fe_sqr(t3, a->y);
	secp256k1_fe_mul_int(t3, 2);
	secp256k1_fe_sqr(t4, t3);
	secp256k1_fe_mul_int(t4, 2);
	secp256k1_fe_mul(t3, t3, a->x);
	secp256k1_fe_cmov(r->x, t3);
	secp256k1_fe_mul_int(r->x, 4);
	secp256k1_fe_negate(r->x, r->x, 4);
	secp256k1_fe_add(r->x, t2);
	secp256k1_fe_negate(t2, t2, 1);
	secp256k1_fe_mul_int(t3, 6);
	secp256k1_fe_add(t3, t2);
	secp256k1_fe_mul(r->y, t1, t3);
	secp256k1_fe_negate(t2, t4, 2);
	secp256k1_fe_add(r->y, t2);
}

SECP256K1_INLINE void secp256k1_gej_add_ge_var( secp256k1_gej *r, secp256k1_gej *a, secp256k1_ge *b, uint32_t *rzr )
{
	uint32_t z12[10], u1[10], u2[10], s1[10], s2[10], h[10], i[10], i2[10], h2[10], h3[10], t[10];

	secp256k1_fe_sqr( z12, a->z );
	secp256k1_fe_cmov( u1, a->x );
	secp256k1_fe_normalize_weak( u1 );
	secp256k1_fe_mul( u2, b->x, z12 );
	secp256k1_fe_cmov( s1, a->y );
	secp256k1_fe_normalize_weak( s1 );
	secp256k1_fe_mul( s2, b->y, z12 );
	secp256k1_fe_mul( s2, s2, a->z );
	secp256k1_fe_negate( h, u1, 1 );
	secp256k1_fe_add( h, u2 );
	secp256k1_fe_negate( i, s1, 1 );
	secp256k1_fe_add( i, s2 );

	if ( rzr != NULL )
	{
		if (secp256k1_fe_normalizes_to_zero_var(h)) {
			if (secp256k1_fe_normalizes_to_zero_var(i)) {
				secp256k1_gej_double_var(r, a, rzr);
			} else {
				if (rzr != NULL) {
					secp256k1_fe_set_int(rzr, 0);
				}
			}
			return;
		}
    }

	secp256k1_fe_sqr( i2, i );
	secp256k1_fe_sqr( h2, h );
	secp256k1_fe_mul( h3, h, h2 );
	if ( rzr != NULL ) secp256k1_fe_cmov( rzr, h );

	secp256k1_fe_mul( r->z, a->z, h );
	secp256k1_fe_mul( t, u1, h2 );
	secp256k1_fe_cmov( r->x, t );
	secp256k1_fe_mul_int( r->x, 2 );
	secp256k1_fe_add( r->x, h3 );
	secp256k1_fe_negate( r->x, r->x, 3 );
	secp256k1_fe_add( r->x, i2 );
	secp256k1_fe_negate( r->y, r->x, 5 );
	secp256k1_fe_add( r->y, t );
	secp256k1_fe_mul( r->y, r->y, i );
	secp256k1_fe_mul( h3, h3, s1 );
	secp256k1_fe_negate( h3, h3, 1 );
	secp256k1_fe_add( r->y, h3 );
}
#endif

SECP256K1_INLINE void secp256k1_gej_add_ge_var_simplified( secp256k1_gej *r, secp256k1_gej *a, secp256k1_ge *b )
{
	uint32_t u1[10], s1[10], s2[10], h[10], i[10], i2[10], h2[10], h3[10], t[10];

	secp256k1_fe_cmov( u1, a->x );
	secp256k1_fe_normalize_weak( u1 );
	secp256k1_fe_cmov( s1, a->y );
	secp256k1_fe_normalize_weak( s1 );
	secp256k1_fe_cmov( s2, b->y );
	secp256k1_fe_negate( h, u1, 1 );
	secp256k1_fe_add( h, b->x );
	secp256k1_fe_negate( i, s1, 1 );
	secp256k1_fe_add( i, s2 );

	secp256k1_fe_sqr( i2, i );
	secp256k1_fe_sqr( h2, h );
	secp256k1_fe_mul( h3, h, h2 );

	secp256k1_fe_mul_simplified1( r->z, h );
	secp256k1_fe_mul( t, u1, h2 );
	secp256k1_fe_cmov( r->x, t );
	secp256k1_fe_mul_int( r->x, 2 );
	secp256k1_fe_add( r->x, h3 );
	secp256k1_fe_negate( r->x, r->x, 3 );
	secp256k1_fe_add( r->x, i2 );
	secp256k1_fe_negate( r->y, r->x, 5 );
	secp256k1_fe_add( r->y, t );
	secp256k1_fe_mul( r->y, r->y, i );
	secp256k1_fe_mul( h3, h3, s1 );
	secp256k1_fe_negate( h3, h3, 1 );
	secp256k1_fe_add( r->y, h3 );
}

#define SECP256K1_FE_CONST_INNER(d7, d6, d5, d4, d3, d2, d1, d0) { \
    (d0) & 0x3FFFFFFUL, \
    (((uint32_t)d0) >> 26) | (((uint32_t)(d1) & 0xFFFFFUL) << 6), \
    (((uint32_t)d1) >> 20) | (((uint32_t)(d2) & 0x3FFFUL) << 12), \
    (((uint32_t)d2) >> 14) | (((uint32_t)(d3) & 0xFFUL) << 18), \
    (((uint32_t)d3) >> 8) | (((uint32_t)(d4) & 0x3UL) << 24), \
    (((uint32_t)d4) >> 2) & 0x3FFFFFFUL, \
    (((uint32_t)d4) >> 28) | (((uint32_t)(d5) & 0x3FFFFFUL) << 4), \
    (((uint32_t)d5) >> 22) | (((uint32_t)(d6) & 0xFFFFUL) << 10), \
    (((uint32_t)d6) >> 16) | (((uint32_t)(d7) & 0x3FFUL) << 16), \
    (((uint32_t)d7) >> 10) \
}
#define SECP256K1_FE_CONST(d7, d6, d5, d4, d3, d2, d1, d0) SECP256K1_FE_CONST_INNER((d7), (d6), (d5), (d4), (d3), (d2), (d1), (d0))
#define SECP256K1_GE_CONST(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) {SECP256K1_FE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), SECP256K1_FE_CONST((i),(j),(k),(l),(m),(n),(o),(p))}

#ifdef OPENCL
__attribute__ ((aligned (64))) __constant secp256k1_ge secp256k1_ge_const_g = SECP256K1_GE_CONST(
	0x79BE667EUL, 0xF9DCBBACUL, 0x55A06295UL, 0xCE870B07UL,
	0x029BFCDBUL, 0x2DCE28D9UL, 0x59F2815BUL, 0x16F81798UL,
	0x483ADA77UL, 0x26A3C465UL, 0x5DA4FBFCUL, 0x0E1108A8UL,
	0xFD17B448UL, 0xA6855419UL, 0x9C47D08FUL, 0xFB10D4B8UL
);
#else
secp256k1_ge secp256k1_ge_const_g = SECP256K1_GE_CONST(
	0x79BE667EUL, 0xF9DCBBACUL, 0x55A06295UL, 0xCE870B07UL,
	0x029BFCDBUL, 0x2DCE28D9UL, 0x59F2815BUL, 0x16F81798UL,
	0x483ADA77UL, 0x26A3C465UL, 0x5DA4FBFCUL, 0x0E1108A8UL,
	0xFD17B448UL, 0xA6855419UL, 0x9C47D08FUL, 0xFB10D4B8UL
);
#endif

SECP256K1_INLINE void secp256k1_ge_set_gej2( secp256k1_ge *r, secp256k1_gej *a )
{
	uint32_t z2[10], z3[10];
	secp256k1_fe_inv(a->z, a->z);
	secp256k1_fe_sqr(z2, a->z);
	secp256k1_fe_mul(z3, a->z, z2);
	secp256k1_fe_mul(a->x, a->x, z2);
	secp256k1_fe_mul(a->y, a->y, z3);
	secp256k1_fe_set_int(a->z, 1);
	secp256k1_fe_cmov(r->x, a->x);
	secp256k1_fe_cmov(r->y, a->y);
}

SECP256K1_INLINE void secp256k1_ge_set_gej_zinv(secp256k1_ge *r, secp256k1_gej *a, uint32_t *zi)
{
	uint32_t zi2[10];
	uint32_t zi3[10];
	secp256k1_fe_sqr(zi2, zi);
	secp256k1_fe_mul(zi3, zi2, zi);
	secp256k1_fe_mul(r->x, a->x, zi2);
	secp256k1_fe_mul(r->y, a->y, zi3);
}

SECP256K1_INLINE void secp256k1_ge_to_storage(__global secp256k1_ge_storage *r, secp256k1_ge *a)
{
	uint32_t x[10], y[10];
	secp256k1_fe_cmov(x, a->x);
	secp256k1_fe_normalize(x);
	secp256k1_fe_cmov(y, a->y);
	secp256k1_fe_normalize(y);
	secp256k1_fe_to_storage(r->x, x);
	secp256k1_fe_to_storage(r->y, y);
}

SECP256K1_INLINE int secp256k1_scalar_shr_int(uint32_t *r, int n) {
    int ret;

    ret = r[0] & ((1 << n) - 1);
    r[0] = (r[0] >> n) + (r[1] << (32 - n));
    r[1] = (r[1] >> n) + (r[2] << (32 - n));
    r[2] = (r[2] >> n) + (r[3] << (32 - n));
    r[3] = (r[3] >> n) + (r[4] << (32 - n));
    r[4] = (r[4] >> n) + (r[5] << (32 - n));
    r[5] = (r[5] >> n) + (r[6] << (32 - n));
    r[6] = (r[6] >> n) + (r[7] << (32 - n));
    r[7] = (r[7] >> n);
    return ret;
}

SECP256K1_INLINE uint64_t secp256k1_scalar_shr_any( uint32_t *s, unsigned int n )
{
	unsigned int cur_shift = 0, offset = 0;
	uint64_t rtn = 0;

	while ( n > 0 )
	{
		cur_shift = ( n > 15 ? 15 : n );

		rtn |= ((uint64_t)secp256k1_scalar_shr_int(s, cur_shift) << (uint64_t)offset);

		offset += cur_shift;
		n      -= cur_shift;
	}

	return rtn;
}

SECP256K1_INLINE void secp256k1_scalar_set_int(uint32_t *r, unsigned int v)
{
	r[0] = v;
	r[1] = 0;
	r[2] = 0;
	r[3] = 0;
	r[4] = 0;
	r[5] = 0;
	r[6] = 0;
	r[7] = 0;
}

SECP256K1_INLINE int secp256k1_scalar_is_zero(uint32_t *a)
{
	return ( a[0] | a[1] | a[2] | a[3] | a[4] | a[5] | a[6] | a[7] ) == 0;
}

SECP256K1_INLINE void secp256k1_scalar_negate( uint32_t *r, const uint32_t *a )
{
	uint64_t t;

	t  = (uint64_t)(~a[0]) + SECP256K1_N_0 + 1; r[0] = t & 0xFFFFFFFFUL; t >>= 32;
	t += (uint64_t)(~a[1]) + SECP256K1_N_1    ; r[1] = t & 0xFFFFFFFFUL; t >>= 32;
	t += (uint64_t)(~a[2]) + SECP256K1_N_2    ; r[2] = t & 0xFFFFFFFFUL; t >>= 32;
	t += (uint64_t)(~a[3]) + SECP256K1_N_3    ; r[3] = t & 0xFFFFFFFFUL; t >>= 32;
	t += (uint64_t)(~a[4]) + SECP256K1_N_4    ; r[4] = t & 0xFFFFFFFFUL; t >>= 32;
	t += (uint64_t)(~a[5]) + SECP256K1_N_5    ; r[5] = t & 0xFFFFFFFFUL; t >>= 32;
	t += (uint64_t)(~a[6]) + SECP256K1_N_6    ; r[6] = t & 0xFFFFFFFFUL; t >>= 32;
	t += (uint64_t)(~a[7]) + SECP256K1_N_7    ; r[7] = t & 0xFFFFFFFFUL;
}

SECP256K1_INLINE int64_t secp256k1_scalar_sdigit_single( uint32_t *s, unsigned int w )
{
	int64_t sdigit = 0;
    int64_t overflow_bit = (int64_t)(1 << w);
    int64_t precomp_max = (int64_t)(1 << (w-1));

	sdigit = (int64_t)secp256k1_scalar_shr_any(s, w);

	if ( sdigit <= precomp_max )
	{
		return sdigit;
	}
	else
	{
		uint32_t one[8];
		secp256k1_scalar_set_int(one, 1);

		sdigit -= overflow_bit;

		secp256k1_scalar_add_big(s, s, one);

		return sdigit;
	}
}

SECP256K1_INLINE size_t secp256k1_scalar_sdigit( int64_t *sdigits, uint32_t *s, unsigned int w )
{
	size_t digits = 0;

	while ( !secp256k1_scalar_is_zero(s) )
	{
		sdigits[ digits ] = secp256k1_scalar_sdigit_single( s, w );
		digits++;
		
		if ( digits == 13 ) break; // just in case
	}

	return digits;
}

SECP256K1_INLINE void secp256k1_ge_neg(secp256k1_ge *r, secp256k1_ge *a)
{
	*r = *a;
	secp256k1_fe_normalize_weak(r->y);
	secp256k1_fe_negate(r->y, r->y, 1);
}

SECP256K1_INLINE void secp256k1_ecmult_big( uint32_t bits, __global secp256k1_gej *r, uint32_t *privkey, __global secp256k1_ge_storage *precomp )
{
	int64_t sdigits[13];
	uint32_t windows = secp256k1_scalar_sdigit( sdigits, privkey, bits );
	
	secp256k1_gej _r;
	secp256k1_ge window_value;
	if ( sdigits[ 0 ] != 0 )
	{
		if ( sdigits[ 0 ] < 0 )
		{
			secp256k1_ge_from_storage( &window_value, &( precomp[ (-(sdigits[ 0 ]) - 1) * windows ] ) );
			secp256k1_ge_neg( &window_value, &window_value );
		}
		else
		{
			secp256k1_ge_from_storage( &window_value, &( precomp[ (+(sdigits[ 0 ]) - 1) * windows ] ) );
		}
		
		secp256k1_fe_cmov(_r.x, window_value.x);
		secp256k1_fe_cmov(_r.y, window_value.y);
	}

	for ( int window = 1; window < windows; window++ )
	{
		int64_t sdigit = sdigits[ window ];

		if ( sdigit != 0 )
		{
			if ( sdigit < 0 )
			{
				secp256k1_ge_from_storage( &window_value, &( precomp[ window + (-(sdigit) - 1) * windows ] ) );
				secp256k1_ge_neg( &window_value, &window_value );
			}
			else
			{
				secp256k1_ge_from_storage( &window_value, &( precomp[ window + (+(sdigit) - 1) * windows ] ) );
			}

			if ( window == 1 )
			{
				secp256k1_gej_add_ge_var_simplified( &_r, &_r, &window_value );
			}
			else
			{
#ifdef OPENCL
				secp256k1_gej_add_ge_var( &_r, &_r, &window_value );
#else
				secp256k1_gej_add_ge_var( &_r, &_r, &window_value, NULL );
#endif
			}
		}
	}
	
	*r = _r;
}

#ifndef OPENCL
void secp256k1_ecmult_big_create( uint32_t bits, secp256k1_gej *gej_temp, uint32_t *z_ratio, secp256k1_ge_storage *precomp )
{
	unsigned int windows;
	size_t window_size, total_size;
	size_t i;

	uint32_t      fe_zinv[10];
	secp256k1_ge  ge_temp;
	secp256k1_ge  ge_window_one = secp256k1_ge_const_g;
	secp256k1_gej gej_window_base;

	windows = (256 / bits) + 1;
	window_size = (1 << (bits - 1));
    total_size = (256 / bits) * window_size + (1 << (256 % bits));

	secp256k1_gej_set_ge( &gej_window_base, &ge_window_one);
	secp256k1_fe_set_int((&(z_ratio[0])), 0);
	
	for ( int row = 0; row < windows; row++ )
	{
		window_size = ( row == windows - 1 ? (1 << (256 % bits)) : (1 << (bits - 1)) );

        if ( row > 0 )
		{
			for ( i = 0; i < bits; i++ ) { secp256k1_gej_double_var( &gej_window_base, &gej_window_base ); }
        }

		gej_temp[ 0 ] = gej_window_base;

		secp256k1_ge_set_gej2( &ge_window_one, &gej_window_base );

		for ( i = 1; i < window_size; i++ )
		{
			secp256k1_gej_add_ge_var( &( gej_temp[ i ] ), &(gej_temp[ i - 1 ]), &ge_window_one, &(z_ratio[i*10]) );
		}

		i = window_size - 1;
		secp256k1_fe_inv(fe_zinv, (gej_temp[i].z));
		secp256k1_ge_set_gej_zinv(&ge_temp, &(gej_temp[i]), fe_zinv);
		secp256k1_ge_to_storage(&(precomp[row + i*windows]), &ge_temp);

		for ( ; i > 0; i-- )
		{
			secp256k1_fe_mul(fe_zinv, fe_zinv, &(z_ratio[i*10]));

			secp256k1_ge_set_gej_zinv(&ge_temp, &(gej_temp[i-1]), fe_zinv);
			secp256k1_ge_to_storage(&(precomp[row + (i-1)*windows]), &ge_temp);
		}
	}
}
#endif

SECP256K1_INLINE void secp256k1_pubkey_save( secp256k1_pubkey *pubkey, secp256k1_ge *ge )
{
	secp256k1_ge_storage s;

	secp256k1_fe_normalize( ge->x );
	secp256k1_fe_normalize( ge->y );
	secp256k1_fe_to_storage( s.x, ge->x );
	secp256k1_fe_to_storage( s.y, ge->y );

	#pragma unroll
	for ( uint32_t i = 0; i < 8; i++ )
	{
		*(uint32_t*)( &pubkey->data[  0 + i * 4 ] ) = s.x[ i ];
		*(uint32_t*)( &pubkey->data[ 32 + i * 4 ] ) = s.y[ i ];
	}
}

SECP256K1_INLINE void secp256k1_pubkey_save_global( __global secp256k1_pubkey *pubkey, secp256k1_ge *ge )
{
	secp256k1_ge_storage s;

	secp256k1_fe_normalize( ge->x );
	secp256k1_fe_normalize( ge->y );
	secp256k1_fe_to_storage( s.x, ge->x );
	secp256k1_fe_to_storage( s.y, ge->y );

	#pragma unroll
	for ( uint32_t i = 0; i < 8; i++ )
	{
		*(__global uint32_t*)( &pubkey->data[  0 + i * 4 ] ) = s.x[ i ];
		*(__global uint32_t*)( &pubkey->data[ 32 + i * 4 ] ) = s.y[ i ];
	}
}

void secp256k1_ec_pubkey_create( uint32_t bits, unsigned char *seckey, __global secp256k1_gej *pj, secp256k1_pubkey *pubkey, __global secp256k1_ge_storage *precomp )
{
	uint32_t sec[8];
	secp256k1_scalar_set_b32( sec, seckey );

	secp256k1_ecmult_big( bits, pj, sec, precomp );

	secp256k1_ge p;
	secp256k1_ge_set_gej_global( &p, pj );

	secp256k1_pubkey_save( pubkey, &p );
}

static int secp256k1_eckey_pubkey_serialize( secp256k1_ge *elem, unsigned char *pub, size_t *size )
{
	secp256k1_fe_normalize_var( elem->x );
	secp256k1_fe_normalize_var( elem->y );
	secp256k1_fe_get_b32_local( &pub[1], elem->x );

	*size = 33;
	pub[0] = 0x02 | ((elem->y[0]&1) ? 0x01 : 0x00);

	return 1;
}

int nonce_function_rfc6979( unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *algo16 )
{
	unsigned char keydata[112];
	int keylen = 64;
	secp256k1_rfc6979_hmac_sha256_t rng;
	unsigned int i;
	/* We feed a byte array to the PRNG as input, consisting of:
	* - the private key (32 bytes) and message (32 bytes), see RFC 6979 3.2d.
	* - optionally 32 extra bytes of data, see RFC 6979 3.6 Additional Data.
	* - optionally 16 extra bytes with the algorithm name.
	* Because the arguments have distinct fixed lengths it is not possible for
	*  different argument mixtures to emulate each other and result in the same
	*  nonces.
	*/
	memcpy(keydata, key32, 32);
	memcpy(keydata + 32, msg32, 32);
	memcpy(keydata + keylen, algo16, 16);
	keylen += 16;
	secp256k1_rfc6979_hmac_sha256_initialize(&rng, keydata, keylen);
	secp256k1_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
	return 1;
}

int secp256k1_schnorr_sig_generate_k( uint32_t *k, const unsigned char *msg32, const uint32_t *privkey )
{
	int overflow = 0;
	int ret = 0;
	unsigned int count = 0;
	unsigned char nonce32[32], seckey[32];

	/* Seed used to make sure we generate different values of k for schnorr */
	const unsigned char secp256k1_schnorr_algo16[17] = "Schnorr+SHA256  ";

	secp256k1_scalar_get_b32( seckey, privkey );

	ret = nonce_function_rfc6979( nonce32, msg32, seckey, secp256k1_schnorr_algo16 );
	secp256k1_scalar_set_b32( k, nonce32 );

    return ret;
}

int secp256k1_schnorr_compute_k_R( uint32_t bits, __global secp256k1_ge_storage *precomp, __global secp256k1_gej *pj, uint32_t *k, secp256k1_ge *R, const unsigned char *msg32, const uint32_t *privkey )
{
	uint32_t kCopy[8];

	if ( !secp256k1_schnorr_sig_generate_k( k, msg32, privkey ) )
	{
		return 0;
	}

	for ( int i = 0; i < 8; i++ ) kCopy[ i ] = k[ i ];
	secp256k1_ecmult_big( bits, pj, kCopy, precomp );
	secp256k1_ge_set_gej_global( R, pj );
	return 1;
}

int secp256k1_schnorr_compute_e( uint32_t *e, const uint32_t *r, secp256k1_ge *p, const unsigned char *msg32 )
{
	int overflow = 0;
	size_t size;
	secp256k1_sha256_t sha;
	unsigned char buf[33];
	secp256k1_sha256_initialize(&sha);

	/* R.x */
	secp256k1_sha256_write(&sha, (unsigned char*)r, 32);

	/* compressed P */
	secp256k1_eckey_pubkey_serialize(p, buf, &size);

	secp256k1_sha256_write(&sha, buf, 33);

	/* msg */
	secp256k1_sha256_write(&sha, msg32, 32);

	/* compute e */
	secp256k1_sha256_finalize( &sha, buf );
	secp256k1_scalar_set_b32( e, buf );
	return !overflow & !secp256k1_scalar_is_zero(e);
}

int secp256k1_schnorr_compute_sig( uint32_t *sig64, const unsigned char *msg32, uint32_t *k, secp256k1_ge *R, const uint32_t *privkey, secp256k1_ge *pubkey )
{
	uint32_t e[8], s[8];

    uint32_t r[10];
	if ( !secp256k1_fe_sqrt_var( r, R->y ) )
	{
		secp256k1_scalar_negate( k, k );
	}

	secp256k1_fe_normalize( R->x );
	secp256k1_fe_get_b32_local( (unsigned char*)sig64, R->x );
	secp256k1_schnorr_compute_e( e, sig64, pubkey, msg32 );
	secp256k1_scalar_mul( s, e, privkey );
	secp256k1_scalar_add_big( s, s, k );
	secp256k1_scalar_get_b32( (unsigned char*)&sig64[ 8 ], s );
	return 1;
}

int secp256k1_schnorr_sig_sign( uint32_t bits, __global secp256k1_ge_storage *precomp, __global secp256k1_gej *pj, uint32_t *sig64, const unsigned char *msg32, uint32_t *privkey, secp256k1_ge *pubkey )
{
	secp256k1_ge R;
	uint32_t k[8]={0};
	int ret;

	if ( !secp256k1_schnorr_compute_k_R( bits, precomp, pj, &k[0], &R, msg32, privkey ) )
	{
		return 0;
	}

	ret = secp256k1_schnorr_compute_sig( sig64, msg32, &k[0], &R, privkey, pubkey );

	return ret;
}

void secp256k1_schnorr_sign( uint32_t bits, __global secp256k1_ge_storage *precomp, __global secp256k1_gej *pj, uint32_t *sig64, unsigned char *msg32, unsigned char *seckey )
{
	secp256k1_pubkey pubkey;
	secp256k1_ge p;
	uint32_t sec[8];

	secp256k1_ec_pubkey_create( bits, seckey, pj, &pubkey, precomp );

	secp256k1_ge_storage s;
	memcpy( (unsigned char*)&s, pubkey.data, 64 );
	secp256k1_ge_from_storage( (&p), (&s) );

    secp256k1_scalar_set_b32( sec, seckey );

	secp256k1_schnorr_sig_sign( bits, precomp, pj, sig64, msg32, sec, &p );

	return;
}

#ifdef OPENCL
__attribute__((reqd_work_group_size(64, 1, 1)))
kernel void nexapow_start( __global uint *hashInput, __global uint32_t *hashOutput, __global uint *nonceBranch, uint intensity, __global secp256k1_gej *pj, __global secp256k1_ge_storage *precomp, uint32_t bits )
{
	if ( get_global_id( 0 ) >= intensity ) return;

	uint gid = get_global_id( 0 );

	uint32_t sec[8];
	uint32_t k[8];
	uint32_t kCopy[8];	

	unsigned char seckey[32];
	unsigned char msg32[32];
	for ( int i = 0; i < 8; i++ ) ((uint32_t*)seckey)[ i ] = hashInput[ gid * 24 + i ];
	for ( int i = 0; i < 8; i++ ) ((uint32_t*)msg32)[ i ] = hashInput[ gid * 24 + 8 + i ];

    secp256k1_scalar_set_b32( sec, seckey );

	secp256k1_schnorr_sig_generate_k( k, msg32, sec );
	for ( int i = 0; i < 8; i++ ) kCopy[ i ] = k[ i ];
	secp256k1_ecmult_big( bits, &pj[ gid ], kCopy, precomp );
	
	secp256k1_ge p;
	secp256k1_ge_set_gej_global( &p, &pj[ gid ] );
		
	__global secp256k1_pubkey *outs = (__global secp256k1_pubkey*)&hashOutput[ gid * 16 ];
	secp256k1_pubkey_save_global( outs, &p );

	__global uint32_t *out = &hashInput[ gid * 24 + 16 ];
	for ( int i = 0; i < 8; i++ ) out[ i ] = k[ i ];
}

__attribute__((reqd_work_group_size(64, 1, 1)))
kernel void nexapow( __global uint *hashInput, __global uchar *hashOutput, __global uint *nonceBranch, uint intensity, __global uint *pubkeyInput, __global uint *pubkeyInput2, __global secp256k1_gej *pj, __global secp256k1_ge_storage *precomp, uint32_t bits )
{
	if ( get_global_id( 0 ) >= intensity ) return;

	uint gid = get_global_id( 0 );

	secp256k1_pubkey pubkey;
	secp256k1_pubkey pubkey2;
	secp256k1_ge p, R;
	uint32_t sec[8];
	uint32_t k[8];

	unsigned char sig64[64];
	unsigned char sig64_2[64];
	unsigned char seckey[32];
	unsigned char msg32[32];
	for ( int i = 0; i < 8; i++ ) ((uint32_t*)seckey)[ i ] = hashInput[ gid * 24 + i ];
	for ( int i = 0; i < 8; i++ ) ((uint32_t*)msg32)[ i ] = hashInput[ gid * 24 + 8 + i ];
	for ( int i = 0; i < 8; i++ ) ((uint32_t*)k)[ i ] = hashInput[ gid * 24 + 16 + i ];
	for ( int i = 0; i < 16; i++ ) ((uint32_t*)pubkey.data)[ i ] = pubkeyInput[ gid * 16 + i ];
	for ( int i = 0; i < 16; i++ ) ((uint32_t*)pubkey2.data)[ i ] = pubkeyInput2[ gid * 16 + i ];

	secp256k1_ge_storage s;
	memcpy( (unsigned char*)&s, pubkey.data, 64 );
	secp256k1_ge_from_storage( (&p), (&s) );
	memcpy( (unsigned char*)&s, pubkey2.data, 64 );
	secp256k1_ge_from_storage( (&R), (&s) );

	secp256k1_scalar_set_b32( sec, seckey );

	secp256k1_schnorr_compute_sig( sig64, msg32, &k[0], &R, sec, &p );

	__global uchar *out = &hashOutput[ gid * 64 ];
	for ( int i = 0; i < 64; i++ ) out[ i ] = sig64[ i ];
}

__attribute__((reqd_work_group_size(64, 1, 1)))
kernel void secp256k1_64( __global uint *hashInput, __global uchar *hashOutput, __global uint *nonceBranch, uint intensity, __global secp256k1_gej *pj, __global secp256k1_ge_storage *precomp, uint32_t bits )
{
	if ( get_global_id( 0 ) >= intensity ) return;

	uint gid = get_global_id( 0 );

	uint32_t sec[8];
	uchar b32[32];
	#pragma unroll
	for ( int i = 0; i < 8; i++ ) ((uint32_t*)b32)[ i ] = hashInput[ gid * 24 + i ];
	secp256k1_scalar_set_b32( sec, b32 );

	secp256k1_ecmult_big( bits, &pj[ gid ], sec, precomp );
	secp256k1_ge p;
	secp256k1_ge_set_gej_global( &p, &pj[ gid ] );
		
	__global secp256k1_pubkey *out = (__global secp256k1_pubkey*)&hashOutput[ gid * 64 ];
	secp256k1_pubkey_save_global( out, &p );
}

__kernel void sha256_64( __global uint *input, __global uint *hashOutput, __global uint *nonceBranch, uint intensity )
{
	if ( get_global_id( 0 ) >= intensity ) return;

	uint gid = get_global_id( 0 ) * 16;
	
	uint SHA256Buf[16];
	#pragma unroll
	for ( int i = 0; i < 16; ++i ) SHA256Buf[ i ] = SWAP4( input[ gid + i ] );

	uint outbuf[ 8 ] = { 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19 };

	sha256_round( SHA256Buf, outbuf );

	SHA256Buf[ 0 ] = 0x80000000;
	#pragma unroll
	for ( int i = 1; i < 15; ++i ) SHA256Buf[ i ] = 0;
	SHA256Buf[ 15 ] = 0x200;

	sha256_round( SHA256Buf, outbuf );
	
	__global uint *out = &hashOutput[ gid ];
	out[ 0 ] = SWAP4( outbuf[ 0 ] );
	out[ 1 ] = SWAP4( outbuf[ 1 ] );
	out[ 2 ] = SWAP4( outbuf[ 2 ] );
	out[ 3 ] = SWAP4( outbuf[ 3 ] );
	out[ 4 ] = SWAP4( outbuf[ 4 ] );
	out[ 5 ] = SWAP4( outbuf[ 5 ] );
	out[ 6 ] = SWAP4( outbuf[ 6 ] );
	out[ 7 ] = SWAP4( outbuf[ 7 ] );

	#pragma unroll
	for ( int i = 8; i < 16; ++i ) out[ i ] = 0;
}

__kernel void sha256_40( __global uint *input, __global uint *hashOutput, __global uint *nonceBranch, uint intensity )
{
	if ( get_global_id( 0 ) - get_global_offset( 0 ) >= intensity ) return;

	uint gid = ( get_global_id( 0 ) - get_global_offset( 0 ) ) * 24;
	
	uint SHA256Buf[16];
	#pragma unroll
	for ( int i = 0; i < 11; ++i ) SHA256Buf[ i ] = SWAP4( input[ i ] );

	uint nonce = get_global_id( 0 );
	SHA256Buf[  9 ] ^= SWAP4( nonce << 8 );
	SHA256Buf[ 10 ] ^= SWAP4( nonce >> 24 );

	uint outbuf[ 8 ] = { 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19 };

	SHA256Buf[ 10 ] ^= 0x800000;
	#pragma unroll
	for ( int i = 11; i < 15; ++i ) SHA256Buf[ i ] = 0;
	SHA256Buf[ 15 ] = 0x148;

	sha256_round( SHA256Buf, outbuf );

	#pragma unroll
	for ( int i = 0; i < 8; ++i ) SHA256Buf[ i ] = outbuf[ i ];

	uint outbuf2[ 8 ] = { 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19 };

	SHA256Buf[ 8 ] = 0x80000000;
	#pragma unroll
	for ( int i = 9; i < 15; ++i ) SHA256Buf[ i ] = 0;
	SHA256Buf[ 15 ] = 0x100;
	
	sha256_round( SHA256Buf, outbuf2 );
	
	__global uint *out = &hashOutput[ gid ];
	out[ 0 ] = SWAP4( outbuf2[ 0 ] );
	out[ 1 ] = SWAP4( outbuf2[ 1 ] );
	out[ 2 ] = SWAP4( outbuf2[ 2 ] );
	out[ 3 ] = SWAP4( outbuf2[ 3 ] );
	out[ 4 ] = SWAP4( outbuf2[ 4 ] );
	out[ 5 ] = SWAP4( outbuf2[ 5 ] );
	out[ 6 ] = SWAP4( outbuf2[ 6 ] );
	out[ 7 ] = SWAP4( outbuf2[ 7 ] );

	#pragma unroll
	for ( int i = 8; i < 24; ++i ) out[ i ] = 0;
}

__kernel void sha256_32( __global uint *input, __global uint *hashOutput, __global uint *nonceBranch, uint intensity )
{
	if ( get_global_id( 0 ) >= intensity ) return;

	uint gid = get_global_id( 0 ) * 24;
	
	uint SHA256Buf[16];
	#pragma unroll
	for ( int i = 0; i < 8; ++i ) SHA256Buf[ i ] = SWAP4( input[ gid + i ] );

	uint outbuf[ 8 ] = { 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19 };

	SHA256Buf[ 8 ] = 0x80000000;
	#pragma unroll
	for ( int i = 9; i < 15; ++i ) SHA256Buf[ i ] = 0;
	SHA256Buf[ 15 ] = 0x100;

	sha256_round( SHA256Buf, outbuf );
	
	__global uint *out = &hashOutput[ gid + 8 ];
	out[ 0 ] = SWAP4( outbuf[ 0 ] );
	out[ 1 ] = SWAP4( outbuf[ 1 ] );
	out[ 2 ] = SWAP4( outbuf[ 2 ] );
	out[ 3 ] = SWAP4( outbuf[ 3 ] );
	out[ 4 ] = SWAP4( outbuf[ 4 ] );
	out[ 5 ] = SWAP4( outbuf[ 5 ] );
	out[ 6 ] = SWAP4( outbuf[ 6 ] );
	out[ 7 ] = SWAP4( outbuf[ 7 ] );
}

bool isHashBelowTarget( __global uint *hash, __global const uint *target )
{
	if ( hash[ 7 ] > target[ 7 ] ) return false;
	if ( hash[ 7 ] < target[ 7 ] ) return true;
	if ( hash[ 6 ] > target[ 6 ] ) return false;
	if ( hash[ 6 ] < target[ 6 ] ) return true;

	if ( hash[ 5 ] > target[ 5 ] ) return false;
	if ( hash[ 5 ] < target[ 5 ] ) return true;
	if ( hash[ 4 ] > target[ 4 ] ) return false;
	if ( hash[ 4 ] < target[ 4 ] ) return true;

	if ( hash[ 3 ] > target[ 3 ] ) return false;
	if ( hash[ 3 ] < target[ 3 ] ) return true;
	if ( hash[ 2 ] > target[ 2 ] ) return false;
	if ( hash[ 2 ] < target[ 2 ] ) return true;

	if ( hash[ 1 ] > target[ 1 ] ) return false;
	if ( hash[ 1 ] < target[ 1 ] ) return true;
	if ( hash[ 0 ] > target[ 0 ] ) return false;

	return true;
}

__kernel void checkhash_64( __global uint *hashInput, __global ulong *nonceOutput, __global const uint *target, const uint intensity )
{
	if ( get_global_id( 0 ) >= intensity ) return;

	uint offset = get_global_id( 0 ) * 16;
	if ( isHashBelowTarget( &hashInput[ offset ], target ) )
	{
		ulong id = atom_inc( &nonceOutput[ 0 ] ) + 1;
		if ( id < 18 )
		{
			nonceOutput[ id ] = get_global_id( 0 );
		}
	}
}
#endif