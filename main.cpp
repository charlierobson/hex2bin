#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <string>
#include <vector>
#include <algorithm>

#include "argcrack.h"



enum
{
   ERR_OK,
   ERR_HELP,
   ERR_SOURCEFILE,
   ERR_DESTFILE,
   ERR_CONVERSION
};

int error(int errnum, const char* format, ...)
{
   va_list ptr;
   va_start(ptr, format);
   printf ("error: ");
   vprintf(format, ptr);
   va_end(ptr);

   return errnum;
}


/*
* Velleman K8048 Programmer for FreeBSD and others.
*
* Copyright (c) 2005-2007 Darron Broad
* All rights reserved.
*
* Licensed under the terms of the BSD license, see file LICENSE
* for details.
*
* $Id: inhx32.c,v 1.31 2008/02/29 17:37:05 darron Exp $
*/

/*
* Get hex nibble
*/
unsigned char
	inhx32_gethexn(char c)
{
	if(c>='0' && c<='9')
		return c-'0';
	if(c>='a' && c<='f')
		return c-'a'+10;
	if(c>='A' && c<='F')
		return c-'A'+10;
	return 0;
}

/*
* Get hex byte
*/
unsigned char inhx32_gethexb(char *s)
{
	if(strlen(s)>1)
		return inhx32_gethexn(s[0]) << 4 | inhx32_gethexn(s[1]);
	return 0;
}

enum
{
	TT_DATA,
	TT_EOF,
	TT_EXTENDED_SEGMENT_ADDRESS,
	TT_START_SEGMENT_ADDRESS,
	TT_EXTENDED_LINEAR_ADDRESS,
	TT_START_LINEAR_ADDRESS
};

const int BB=1;
const int AAAA=3;
const int TT=7;
const int HHHH=9;

unsigned short updateCRC(unsigned char data, unsigned short crc)
{
	crc  = (unsigned char)(crc >> 8) | (crc << 8);
	crc ^= data;
	crc ^= (unsigned char)(crc & 0xff) >> 4;
	crc ^= (crc << 8) << 4;
	crc ^= ((crc & 0xff) << 4) << 1;

	return crc;
}

unsigned char memblk[65536];

/*
* inhx32 format parser
*
* returns the number of ordered lines in the inhx32_pdata array after parsing filename
*/
int inhx32(const char *filename, unsigned int lwm, unsigned int hwm)
{
	unsigned int extended_address=0, total_bytes=0, bb, ix, n;
	unsigned char tt=TT_DATA, cc;
	unsigned short aaaa;
	int inhx32_count=0;

	FILE* f1 = fopen(filename, "rb");
	if(!f1)
	{
		printf("error: file open failed [%s]\n", filename);
		return -1;
	}

	char* line = (char*)malloc(1024);
	if(line==NULL)
	{
		printf("%s: fatal error: calloc failed\n", __FUNCTION__);
		exit(-1); /* panic */
	}

	memset(memblk, 0xff, 65536);
	unsigned long first = 65536;
	unsigned long last = 0;

	while(tt!=TT_EOF && fgets(line, 1024, f1)!=NULL)
	{
		line[1023]='\0';

		/* strip CRLF */
		int nnn=strlen(line)-1;
		while(nnn>=0 && (line[nnn]=='\n' || line[nnn]=='\r'))
			line[nnn--]='\0';

		/* validate line prefix and length */
		if(line[0]!=':' || (strlen(line)&1)==0 || strlen(line)<11)
		{
			printf("warning: ignoring malformed line: invalid format [%s]\n", line);
			continue;
		}

		/* validate checksum */
		cc=0;
		for(n=1; line[n]; n+=2)
			cc+=inhx32_gethexb(&line[n]);
		if(cc!=0)
		{
			printf("warning: ignoring malformed line: invalid checksum [%d]\n", cc);
			continue;
		}

		/* determine number of data bytes in this line */
		bb= inhx32_gethexb(&line[BB]);

		/* validate line length */
		if(strlen(line)!=(2*bb+11))
		{
			printf("warning: ignoring malformed line: invalid length [%s]\n", line);
			continue;
		}

		/* determine data address for this line */
		aaaa= (inhx32_gethexb(&line[AAAA]) << 8) | inhx32_gethexb(&line[AAAA+2]);

		/* determine record type */
		tt= inhx32_gethexb(&line[TT]);

		switch(tt)
		{
		case TT_DATA:
			{
				if(bb==0)
				{
					printf("warning: ignoring empty line\n");
					break;
				}
				if ((extended_address | aaaa) < lwm ||
					(extended_address | aaaa) >= hwm)
				{
					printf("info: ignoring out-of-range data @ %04x\n", extended_address | aaaa);
					break;
				}

				++inhx32_count;

				/* save address and word count */
				unsigned int address = extended_address | aaaa;

				if (address < first)
					first = address;

				/* extract data */
				ix=HHHH;
				for(n=0; n<bb; n++)
				{
					memblk[address + n] = inhx32_gethexb(&line[ix]);
					ix+=2;
				}

				if (address + bb > last)
					last = address + bb;
			}
			break;

		case TT_EOF:    break;

		case TT_EXTENDED_SEGMENT_ADDRESS:
			printf("warning: ignoring unhandled extended segment address\n");
			break;

		case TT_START_SEGMENT_ADDRESS:
			printf("warning: ignoring unhandled start segment address\n");
			break;

		case TT_EXTENDED_LINEAR_ADDRESS:
			if(aaaa==0 && bb==2)
				extended_address= (inhx32_gethexb(&line[HHHH]) << 24) | (inhx32_gethexb(&line[HHHH+2]) << 16);
			else
				printf("warning: ignoring invalid extended linear address [aaaa=%04x, bb=%d]\n", aaaa, bb);
			break;

		case TT_START_LINEAR_ADDRESS:
			printf("warning: ignoring unhandled start linear address\n");
			break;

		default:        printf("warning: ignoring unknown record type [%d]\n", tt);
			break;
		}
	}
	free(line);
	fclose(f1);

	/* return error if no data lines found */
	if(inhx32_count==0)
	{
		return error(-5, "file contains no data records [%s]\n", filename);
	}

	total_bytes = last - lwm;

	printf("Decoded %08x -> %08x\nProgram bytes = %08x or %dKB\nlo = 0x%x, hi = 0x%x\n", (unsigned int)first, (unsigned int)last, total_bytes, ((total_bytes + 1023) / 1024), lwm, hwm);

	return last;
}



int main(int argc, char** argv)
{
	argcrack args(argc, argv);

	// todo:
	// option to pad to upper limit?

	if (args.ispresent("-?") || args.ispresent("/?") || args.ispresent("?"))
	{
		printf("ihexdump V1.1\n\n");
		printf("Usage:\n");
		printf("ihexdump {src hex file} (out={dst bin file}) (lo={(0x)n}) (hi={(0x)n}) (raw)\n\n");
		printf("  out=   : target filename (default = {source name}.bin\n");
		printf("   lo=   : start address of range limit (default 0x1000)\n");
		printf("   hi=   : end address of range limit (default 0x10000)\n");
		printf("  raw    : do not write header\n");
		printf("\n");
		return ERR_HELP;
	}

	// desired memory address range - anything outside this is ignored
	//
	int lo = 0x1000, hi = 0x10000;

	std::string inName;
	if (!args.getat(1, inName))
	{
		return error(ERR_SOURCEFILE, "no source filename specified\n");
	}

	std::string outName(inName);
	if (!args.getstring("out=", outName))
	{
		if (!pathutil::changeextension(outName, ".bin") || outName == inName)
		{
			return error(ERR_DESTFILE, "cannot generate destination name - specify one with 'out='\n");
		}
	}

	args.getint("lo=", lo);
	args.getint("hi=", hi);

	int finalAddr = inhx32(argv[1], lo, hi);
	if (finalAddr > 0)
	{
		FILE* output = fopen(outName.c_str(), "wb");
		if (output)
		{
			int finalLen = ((finalAddr - lo + 511) / 512) * 512;

			if (!args.ispresent("raw"))
			{
				unsigned short crc = 0xffff;
				for (int i = lo; i < lo + 0x2000; ++i)
				{
					crc = updateCRC(memblk[i], crc);
				}

				fputs("SMB!", output);
				fwrite(&crc, 2, 1, output);

				crc = 0xffff;
				for (int i = lo; i < lo + finalLen; ++i)
				{
					crc = updateCRC(memblk[i], crc);
				}

				fwrite(&crc, 2, 1, output);
				fwrite(&finalLen, 2, 1, output);

				int offs = ftell(output);
				unsigned char blanks[512] = { 0 };

				fwrite(blanks, 1, 512-offs, output);
			}

			fwrite(&memblk[lo], 1, finalLen, output);
			fclose(output);
		}
		else
		{
			return error(ERR_DESTFILE, "file open failed [%s]\n", outName.c_str());
		}
	}
	else
	{
		return error(ERR_CONVERSION, "conversion failed\n");
	}
}
