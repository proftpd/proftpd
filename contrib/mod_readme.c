/* notify the user when a given file was last changed
 *
 * Configuration:
 *   DisplayReadme <file>
 *
 * "DisplayReadme Readme" will tell the user when "Readme" on the current 
 * working directory was last changed. When cwd is changed (cd, cdup, ...)
 * it'll seach for Readme agin in it and also display it's last changing dates.
 * if found.
 */

#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <conf.h>

/* Flood: Nov 1, 1998
 *
 * The original logic was slightly off, using find_config in recursive mode
 * starting from the server root, which caused all DisplayReadme entries
 * to be evaluated, even if not actually part of the "closest" context
 * (i.e. picking up ALL Anonymous blocks)
 */

static
void add_readme_response(const char *file)
{
	int days;
	time_t clock;

	struct stat buf;
	struct tm *tp;
	
	if(fs_stat(file,&buf) == 0) {
		(void) time(&clock);
		tp = localtime(&clock);
		days = 365 * tp->tm_year + tp->tm_yday;
		tp = localtime(&buf.st_mtime);
		days -= 365 * tp->tm_year + tp->tm_yday;
		add_response(R_DUP, "Please read the file %s",file);
		add_response(R_DUP, "   it was last modified on %.24s - %i day%s ago",
			     ctime(&buf.st_mtime),
		             days, 
		             days == 1 ? "" : "s" );
	}
}
		
MODRET
show_readme(cmd_rec *cmd)
{
	config_rec *c;
	char *file;
	
	c = find_config(CURRENT_CONF, CONF_PARAM, "DisplayReadme", FALSE);
	while(c) {
		file = c->argv[0];
		
		log_debug(DEBUG5,"checking for display file %s", file);
		add_readme_response(file);
		
		c = find_config_next(c, c->next, CONF_PARAM, "DisplayReadme",FALSE);
	}
	/* Originally this returned HANDLED, which was incorrect, and
	 * could cause other POST_CMD handlers to not run
	 */

	return DECLINED(cmd);
}

MODRET 
readme_add_file (cmd_rec *cmd) 
{
	config_rec *c;
	
	CHECK_CONF(cmd,CONF_ROOT|CONF_VIRTUAL|CONF_ANON|CONF_GLOBAL);
	
	if( cmd->argc < 2 )
	{
		CONF_ERROR( cmd, "at least one argument required" );
	}
	else if( cmd->argc > 2 )
	{
		CONF_ERROR( cmd, "only the first argument is evluated in the moment" );
	}
	c = add_config_param_str( "DisplayReadme", 1, (void *)cmd->argv[1]);
	c->flags |= CF_MERGEDOWN;

	log_debug( DEBUG5, "added file %s to readme-list", cmd->argv[1]);

	return HANDLED(cmd);
}

conftable readme_config[] = {
	{ "DisplayReadme",	readme_add_file,	},
	{ NULL }
};

cmdtable readme_commands[] = {
	{ POST_CMD,	C_CWD,	G_NONE,	show_readme,	FALSE,	FALSE },
	{ POST_CMD,	C_CDUP,	G_NONE,	show_readme,	FALSE,	FALSE },
	{ POST_CMD,	C_XCWD,	G_NONE,	show_readme,	FALSE,	FALSE },
	{ POST_CMD,	C_XCUP,	G_NONE,	show_readme,	FALSE,	FALSE },

	{ POST_CMD,	C_PASS,	G_NONE, show_readme,	FALSE,	FALSE },

	{ 0,		NULL }
};

module readme_module = {
	NULL, NULL,		/* Always NULL */
	0x20,			/* API Version 2.0 */
	"readme",
	readme_config,		/* configuration table */
	readme_commands,	/* command table is for local use only */
	NULL,			/* No authentication handlers */
	NULL,			/* Initialization function */
	NULL			/* Post-fork "child mode" init */
};

