#pragma OPENCL EXTENSION cl_khr_int64_base_atomics : enable

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