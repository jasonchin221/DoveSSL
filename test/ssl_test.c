#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "ds_types.h"
#include "ds_errno.h"

static const char *
ds_program_version = "1.0.0";//PACKAGE_STRING;

static const struct option 
ds_long_opts[] = {
	{"help", 0, 0, 'H'},
	{"sn", 0, 0, 'S'},
	{"verify", 0, 0, 'V'},
	{"inject", 0, 0, 'I'},
	{"crypto", 0, 0, 'C'},
	{"decompress", 0, 0, 'D'},
	{"data", 0, 0, 'd'},
	{0, 0, 0, 0}
};

static const char *
ds_options[] = {
	"--data         -d	Data\n",	
	"--sn           -S	SN generate\n",	
	"--verify       -V	Verify license data\n",	
	"--inject       -I	Inject license data\n",	
	"--crypto       -C	encrypt data\n",	
	"--decompress   -D	decompress license data\n",	
	"--help         -H	Print help information\n",	
};

static void 
ds_help(void)
{
	int     index;

	fprintf(stdout, "Version: %s\n", ds_program_version);

	fprintf(stdout, "\nOptions:\n");
	for(index = 0; index < sizeof(ds_options)/sizeof(ds_options[0]);
                    index++) {
		fprintf(stdout, "  %s", ds_options[index]);
	}
}

static const char *
ds_optstring = "HSVICDTd:";

int
main(int argc, char **argv)  
{
    int         c = 0;

    while((c = getopt_long(argc, argv, 
                    ds_optstring,  ds_long_opts, NULL)) != -1) {
        switch(c) {
            case 'H':
                ds_help();
                return DS_OK;

            default:
                ds_help();
                return -DS_ERROR;
        }
    }

    return 0;
}
