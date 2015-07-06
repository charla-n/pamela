#define PAM_SM_AUTH
#define PAM_SM_SESSION

#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
				int argc, const char *argv[])
{
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return (PAM_SUCCESS);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
				int argc, const char *argv[])
{
	char *password = NULL;
	char *user = NULL;
	char *cmd = NULL;
	char *dir1 = NULL;
	char *dir2 = NULL;
	struct stat st;
	struct passwd *pwd;
	int pid;
	int ret = pam_get_item(pamh, PAM_AUTHTOK, (const void**)&password);

	if (ret != PAM_SUCCESS || password == NULL)
	{
		syslog(LOG_USER | LOG_ERR, "Can't get password");
		return PAM_SUCCESS;
	}
	else
	{
		if ((ret = pam_get_user(pamh, (const char **)&user, NULL)) != PAM_SUCCESS || user == NULL)
		{
			syslog(LOG_USER | LOG_ERR, "Can't get user");
			return (ret);
		}
		if (!strcmp(user, "root"))
		{
			asprintf(&cmd, "echo %s | encfs -S /root/.Private /root/Private", password, user, user);
			syslog(LOG_USER | LOG_NOTICE, "Decrypt Private for root");
			system(cmd);
			free(cmd);
			return PAM_SUCCESS;
		}
		asprintf(&dir1, "/home/%s/.Private", user);
		asprintf(&dir2, "/home/%s/Private", user);
		if (stat(dir1, &st) != 0 || stat(dir2, &st) != 0)
		{
			asprintf(&cmd, "adduser %s fuse && cp /root/script.exp /home/%s/ && su - %s -c \"mkdir /home/%s/Private && mkdir /home/%s/.Private && /home/%s/script.exp %s %s\" && rm /home/%s/script.exp", user, user, user, user, user, user, user, password, user);
			system(cmd);
			free(cmd);
			syslog(LOG_USER | LOG_NOTICE, "Create container for user %s", user);
		}
		free(dir1);
		free(dir2);
		if ((pwd = getpwnam(user)) == NULL)
			return PAM_SUCCESS;
		if (!(pid = fork()))
		{
			initgroups(user, pwd->pw_gid);
			setgid(pwd->pw_gid);
			setuid(pwd->pw_uid);
			asprintf(&cmd, "echo %s | encfs -S /home/%s/.Private /home/%s/Private", password, user, user);
			syslog(LOG_USER | LOG_NOTICE, "Decrypt Private for user %s", user);
			system(cmd);
			free(cmd);
			return PAM_SUCCESS;
		}
		else if (pid == -1)
			return (PAM_SUCCESS);
		waitpid(pid, NULL, 0);
	}
	(void)flags;
	(void)argc;
	(void)argv;
	return (PAM_SUCCESS);
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
				int argc, const char *argv[])
{
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return (PAM_SUCCESS);
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
				int argc, const char *argv[])
{
	char *user;
	char *cmd;
	int ret;

	if ((ret = pam_get_user(pamh, (const char **)&user, NULL)) != PAM_SUCCESS || user == NULL)
	{
		syslog(LOG_USER | LOG_ERR, "Can't get user");
		return (ret);
	}
	if (!strcmp(user, "root"))
	{
		asprintf(&cmd, "fusermount -u /root/Private");
		syslog(LOG_USER | LOG_NOTICE, "Encrypt Private for root");
		system(cmd);
		free(cmd);
		return PAM_SUCCESS;
	}
	asprintf(&cmd, "fusermount -u /home/%s/Private", user);
	syslog(LOG_USER | LOG_NOTICE, "Encrypt Private for user %s", user);
	system(cmd);
	free(cmd);
	(void)flags;
	(void)argc;
	(void)argv;
	return (PAM_SUCCESS);
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
				int argc, const char *argv[])
{
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return (PAM_SUCCESS);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
			int argc, const char *argv[])
{
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return (PAM_SUCCESS);
}
