/* @(#) $Id$ */

/* Copyright (C) 2006 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include <stdio.h>
#include <string.h>
#include "sha1_op.h"

/* Openssl sha1 
 * Only use if open ssl is not available.
#ifndef USE_OPENSSL
#include "sha.h"
#include "sha_locl.h"
#else
#include <openssl/sha.h>  
#endif
*/

#include "sha.h"
#include "sha_locl.h"


 
int OS_SHA1_File(char * fname, char * output)
{
    SHA_CTX c;
    FILE *fp;
    char tmpstr[4];
    unsigned char buf[2048 +1];
    unsigned char md[SHA_DIGEST_LENGTH];
    int n;
    
    tmpstr[3] = '\0';
    memset(output,0, 65);
    buf[2048] = '\0';
    
    fp = fopen(fname,"r");
    if(!fp)
        return(-1);
    
    SHA1_Init(&c);
    while((n = fread(buf, 1, 2048, fp)) > 0)
        SHA1_Update(&c,buf,(unsigned long)n);
    
    SHA1_Final(&(md[0]),&c);
    
    for (n=0; n<SHA_DIGEST_LENGTH; n++)
    {
        snprintf(tmpstr, 3, "%02x", md[n]);
        strncpy(output + (n * 2), tmpstr, 3);
    }
                
    /* Closing it */
    fclose(fp);
        
    return(0);
}


/* EOF */