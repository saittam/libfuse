/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/wait.h>

#ifdef linux
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#endif

#include "fuse_opt.h"
#include "fuse_lowlevel.h"

static char *progname;

static char *xstrdup(const char *s)
{
	char *t = strdup(s);
	if (!t) {
		fprintf(stderr, "%s: failed to allocate memory\n", progname);
		exit(1);
	}
	return t;
}

static void *xrealloc(void *oldptr, size_t size)
{
	void *ptr = realloc(oldptr, size);
	if (!ptr) {
		fprintf(stderr, "%s: failed to allocate memory\n", progname);
		exit(1);
	}
	return ptr;
}

static void add_arg(char **cmdp, const char *opt)
{
	size_t optlen = strlen(opt);
	size_t cmdlen = *cmdp ? strlen(*cmdp) : 0;
	if (optlen >= (SIZE_MAX - cmdlen - 4)/4) {
		fprintf(stderr, "%s: argument too long\n", progname);
		exit(1);
	}
	char *cmd = xrealloc(*cmdp, cmdlen + optlen * 4 + 4);
	char *s;
	s = cmd + cmdlen;
	if (*cmdp)
		*s++ = ' ';

	*s++ = '\'';
	for (; *opt; opt++) {
		if (*opt == '\'') {
			*s++ = '\'';
			*s++ = '\\';
			*s++ = '\'';
			*s++ = '\'';
		} else
			*s++ = *opt;
	}
	*s++ = '\'';
	*s = '\0';
	*cmdp = cmd;
}

static char *add_option(const char *opt, char *options)
{
	int oldlen = options ? strlen(options) : 0;

	options = xrealloc(options, oldlen + 1 + strlen(opt) + 1);
	if (!oldlen)
		strcpy(options, opt);
	else {
		strcat(options, ",");
		strcat(options, opt);
	}
	return options;
}

static int prepare_fuse_fd(const char *mountpoint, const char* subtype,
			   const char *options)
{
	int subtype_len = strlen(subtype) + 9;
	char* options_copy = xrealloc(NULL, subtype_len);
	snprintf(options_copy, subtype_len, "subtype=%s", subtype);
	options_copy = add_option(options, options_copy);

	const char *argv[] = { progname, "-o", options_copy };
	struct fuse_args args = FUSE_ARGS_INIT(sizeof(argv) / sizeof(argv[0]),
					       (char**) argv);
	struct fuse_lowlevel_ops dummy_ops;
	memset(&dummy_ops, 0, sizeof(dummy_ops));
	struct fuse_session *session = fuse_session_new(
			&args, &dummy_ops, sizeof(dummy_ops), NULL);
	free(options_copy);
	if (session == NULL || fuse_session_mount(session, mountpoint) == -1) {
		exit(1);
	}

	/*
	 * Duplicate the FUSE file descriptor to obtain a copy that's still
	 * valid after fuse_session_destroy closes its copy. Note that this
	 * conveniently also gives us a file descriptor with the CLOEXEC flag
	 * clear, which is required to pass it across exec.
	 */
	int fuse_fd = fuse_session_fd(session);
	fuse_fd = dup(fuse_fd);
	if (fuse_fd == -1) {
		fprintf(stderr, "%s: Failed to duplicate FUSE fd: %s\n",
			progname, strerror(errno));
		exit(1);
	}
	fuse_session_destroy(session);

	return fuse_fd;
}

#ifdef linux
static void set_capabilities(uint64_t caps)
{
	/*
	 * This invokes the capset syscall directly to avoid the libcap
	 * dependency, which isn't really justified just for this.
	 */
	struct __user_cap_header_struct header = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = 0,
	};
	struct __user_cap_data_struct data[2];
	memset(data, 0, sizeof(data));
	data[0].effective = data[0].permitted = caps;
	data[1].effective = data[1].permitted = caps >> 32;
	if (syscall(SYS_capset, &header, data) == -1) {
		fprintf(stderr, "%s: Failed to drop capabilities: %s\n",
			progname, strerror(errno));
		exit(1);
	}
}

static void drop_privileges(void)
{
	/* Set and lock securebits. */
	if (prctl(PR_SET_SECUREBITS,
		  SECBIT_KEEP_CAPS_LOCKED |
		  SECBIT_NO_SETUID_FIXUP |
		  SECBIT_NO_SETUID_FIXUP_LOCKED |
		  SECBIT_NOROOT |
		  SECBIT_NOROOT_LOCKED) == -1) {
		fprintf(stderr, "%s: Failed to set securebits %s\n",
			progname, strerror(errno));
		exit(1);
	}

	/* Clear the capability bounding set. */
	for (int cap = 0; ; cap++) {
		int cap_status = prctl(PR_CAPBSET_READ, cap);
		if (cap_status == 0) {
			continue;
		}
		if (cap_status == -1 && errno == EINVAL) {
			break;
		}

		if (cap_status != 1) {
			fprintf(stderr,
				"%s: Failed to get capability %u: %s\n",
				progname, cap, strerror(errno));
			exit(1);
		}
		if (prctl(PR_CAPBSET_DROP, cap) == -1) {
			fprintf(stderr,
				"%s: Failed to drop capability %u: %s\n",
				progname, cap, strerror(errno));
		}
	}

	/* Drop capabilities. */
	set_capabilities(0);

	/* Prevent re-acquisition of privileges. */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
		fprintf(stderr, "%s: Failed to set no_new_privs: %s\n",
			progname, strerror(errno));
		exit(1);
	}
}
#endif

int main(int argc, char *argv[])
{
	char *type = NULL;
	char *source;
	const char *mountpoint;
	char *basename;
	char *options = NULL;
	char *command = NULL;
	char *setuid_name = NULL;
	int i;
	int dev = 1;
	int suid = 1;
	int pass_fuse_fd = 0;
	int unprivileged = 0;

	progname = argv[0];
	basename = strrchr(argv[0], '/');
	if (basename)
		basename++;
	else
		basename = argv[0];

	if (strncmp(basename, "mount.fuse.", 11) == 0)
		type = basename + 11;
	if (strncmp(basename, "mount.fuseblk.", 14) == 0)
		type = basename + 14;

	if (type && !type[0])
		type = NULL;

	if (argc < 3) {
		fprintf(stderr,
			"usage: %s %s destination [-t type] [-o opt[,opts...]]\n",
			progname, type ? "source" : "type#[source]");
		exit(1);
	}

	source = argv[1];
	if (!source[0])
		source = NULL;

	mountpoint = argv[2];

	for (i = 3; i < argc; i++) {
		if (strcmp(argv[i], "-v") == 0) {
			continue;
		} else if (strcmp(argv[i], "-t") == 0) {
			i++;

			if (i == argc) {
				fprintf(stderr,
					"%s: missing argument to option '-t'\n",
					progname);
				exit(1);
			}
			type = argv[i];
			if (strncmp(type, "fuse.", 5) == 0)
				type += 5;
			else if (strncmp(type, "fuseblk.", 8) == 0)
				type += 8;

			if (!type[0]) {
				fprintf(stderr,
					"%s: empty type given as argument to option '-t'\n",
					progname);
				exit(1);
			}
		} else	if (strcmp(argv[i], "-o") == 0) {
			char *opts;
			char *opt;
			i++;
			if (i == argc)
				break;

			opts = xstrdup(argv[i]);
			opt = strtok(opts, ",");
			while (opt) {
				int j;
				int ignore = 0;
				const char *ignore_opts[] = { "",
							      "user",
							      "nofail",
							      "nouser",
							      "users",
							      "auto",
							      "noauto",
							      "_netdev",
							      NULL};
				if (strncmp(opt, "setuid=", 7) == 0) {
					setuid_name = xstrdup(opt + 7);
					ignore = 1;
				} else if (strcmp(opt, "unprivileged") == 0) {
					pass_fuse_fd = 1;
					unprivileged = 1;
					ignore = 1;
				}
				for (j = 0; ignore_opts[j]; j++)
					if (strcmp(opt, ignore_opts[j]) == 0)
						ignore = 1;

				if (!ignore) {
					if (strcmp(opt, "nodev") == 0)
						dev = 0;
					else if (strcmp(opt, "nosuid") == 0)
						suid = 0;

					options = add_option(opt, options);
				}
				opt = strtok(NULL, ",");
			}
		}
	}

	if (dev)
		options = add_option("dev", options);
	if (suid)
		options = add_option("suid", options);

	if (!type) {
		if (source) {
			type = xstrdup(source);
			source = strchr(type, '#');
			if (source)
				*source++ = '\0';
			if (!type[0]) {
				fprintf(stderr, "%s: empty filesystem type\n",
					progname);
				exit(1);
			}
		} else {
			fprintf(stderr, "%s: empty source\n", progname);
			exit(1);
		}
	}

#ifdef linux
	if (unprivileged) {
		/*
		 * Make securebits more permissive before calling setuid().
		 * Specifically, if SECBIT_KEEP_CAPS and SECBIT_NO_SETUID_FIXUP
		 * weren't set, setuid() would have the side effect of dropping
		 * all capabilities, and we need to retain CAP_SETPCAP in order
		 * to drop all privileges before exec().
		 */
		if (prctl(PR_SET_SECUREBITS,
			  SECBIT_KEEP_CAPS | SECBIT_NO_SETUID_FIXUP) == -1) {
			fprintf(stderr, "%s: Failed to set securebits %s\n",
				progname, strerror(errno));
			exit(1);
		}
	}
#endif

	if (setuid_name && setuid_name[0]) {
		struct passwd *pwd = getpwnam(setuid_name);
		if (setgid(pwd->pw_gid) == -1 || setuid(pwd->pw_uid) == -1) {
			fprintf(stderr, "%s: Failed to setuid to %s: %s\n",
				progname, setuid_name, strerror(errno));
			exit(1);
		}
	} else if (!getenv("HOME")) {
		/* Hack to make filesystems work in the boot environment */
		setenv("HOME", "/root", 0);
	}

	if (pass_fuse_fd)  {
		int fuse_fd = prepare_fuse_fd(mountpoint, type, options);
		char *dev_fd_mountpoint = xrealloc(NULL, 20);
		snprintf(dev_fd_mountpoint, 20, "/dev/fd/%u", fuse_fd);
		mountpoint = dev_fd_mountpoint;
	}

#ifdef linux
	if (unprivileged) {
		drop_privileges();
	}
#endif
	add_arg(&command, type);
	if (source)
		add_arg(&command, source);
	add_arg(&command, mountpoint);
	if (options) {
		add_arg(&command, "-o");
		add_arg(&command, options);
	}

	execl("/bin/sh", "/bin/sh", "-c", command, NULL);
	fprintf(stderr, "%s: failed to execute /bin/sh: %s\n", progname,
		strerror(errno));
	return 1;
}
