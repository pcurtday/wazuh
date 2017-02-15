/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "log.h"
#include "alerts.h"
#include "getloglocation.h"
#include "rules.h"
#include "eventinfo.h"
#include "config.h"


/* Drop/allow patterns */
static OSMatch FWDROPpm;
static OSMatch FWALLOWpm;

/* Allow custom alert output tokens */
typedef enum e_custom_alert_tokens_id {
    CUSTOM_ALERT_TOKEN_TIMESTAMP = 0,
    CUSTOM_ALERT_TOKEN_FTELL,
    CUSTOM_ALERT_TOKEN_RULE_ALERT_OPTIONS,
    CUSTOM_ALERT_TOKEN_HOSTNAME,
    CUSTOM_ALERT_TOKEN_LOCATION,
    CUSTOM_ALERT_TOKEN_RULE_ID,
    CUSTOM_ALERT_TOKEN_RULE_LEVEL,
    CUSTOM_ALERT_TOKEN_RULE_COMMENT,
    CUSTOM_ALERT_TOKEN_SRC_IP,
    CUSTOM_ALERT_TOKEN_DST_USER,
    CUSTOM_ALERT_TOKEN_FULL_LOG,
    CUSTOM_ALERT_TOKEN_RULE_GROUP,
    CUSTOM_ALERT_TOKEN_LAST
} CustomAlertTokenID;

static const char CustomAlertTokenName[CUSTOM_ALERT_TOKEN_LAST][15] = {
    { "$TIMESTAMP" },
    { "$FTELL" },
    { "$RULEALERT" },
    { "$HOSTNAME" },
    { "$LOCATION" },
    { "$RULEID" },
    { "$RULELEVEL" },
    { "$RULECOMMENT" },
    { "$SRCIP" },
    { "$DSTUSER" },
    { "$FULLLOG" },
    { "$RULEGROUP" },
};

/* Store the events in a file
 * The string must be null terminated and contain
 * any necessary new lines, tabs, etc.
 */
void OS_Store(const Eventinfo *lf)
{
    if (strcmp(lf->location, "ossec-keepalive") == 0) {
        return;
    }
    if (strstr(lf->location, "->ossec-keepalive") != NULL) {
        return;
    }

    fprintf(_eflog,
            "%d %s %02d %s %s%s%s %s\n",
            lf->year,
            lf->mon,
            lf->day,
            lf->hour,
            lf->hostname != lf->location ? lf->hostname : "",
            lf->hostname != lf->location ? "->" : "",
            lf->location,
            lf->full_log);

    fflush(_eflog);
    return;
}

void OS_LogOutput(Eventinfo *lf)
{
    int i;

#ifdef LIBGEOIP_ENABLED
    if (Config.geoipdb_file) {
        if (lf->srcip && !lf->srcgeoip) {
            lf->srcgeoip = GetGeoInfobyIP(lf->srcip);
        }
        if (lf->dstip && !lf->dstgeoip) {
            lf->dstgeoip = GetGeoInfobyIP(lf->dstip);
        }
    }
#endif

    printf(
    "-- BEGIN ALERT --\n"
    "AlertId: %ld.%ld\n"
    "Group: %s\n"
    "Year: %d\n"
    "Month: %s\n"
    "Day: %02d\n"
    "Time: %s\n"
    "Hostname: %s\n"
    "Location: %s\n"
    "RuleId: %d\n"
    "FiredTimes: %d\n"
    "Level: %d\n"
    "Cve: %s\n"
    "Action: %s\n"
    "Comment: '%s'\n"
    "ProgramName: %s\n"
    "Url: %s\n"
    "Status: %s\n"
    "Protocol: %s\n"
    "SourceIp: %s\n"
    "SourceLocation: %s\n"
    "SourcePort: %s\n"
    "DestinationIp: %s\n"
    "DestLocation: %s\n"
    "DestPort: %s\n"
    "Username: %s\n"
    "Filename: %s\n"
    "PermBefore: %d\n"
    "PermAfter: %d\n"
    "Md5Before: %s\n"
    "Md5After: %s\n"
    "Sha1Before: %s\n"
    "Sha1After: %s\n"
    "SizeBefore: %s\n"
    "SizeAfter: %s\n"
    "OwnerBefore: %s\n"
    "OwnerAfter: %s\n"
    "GroupBefore: %s\n"
    "GroupAfter: %s\n"
    "DateBefore: %s\n"
    "DateAfter: %s\n"
    "InodeBefore: %ld\n"
    "InodeAfter: %ld\n"
    "Change: %s\n"
    "FullLog: %.1256s\n",
    (long int)lf->time,
    __crt_ftell,
    lf->generated_rule->group == NULL ? "" : lf->generated_rule->group,
    lf->year,
    lf->mon,
    lf->day,
    lf->hour,
    lf->hostname == NULL ? "" : lf->hostname,
    lf->location == NULL ? "" : lf->location,
    lf->generated_rule->sigid,
    lf->generated_rule->firedtimes,
    lf->generated_rule->level,
    lf->generated_rule->cve == NULL ? "" : lf->generated_rule->cve,
    lf->action == NULL ? "" : lf->action,
    lf->generated_rule->comment == NULL ? "" : lf->generated_rule->comment,
    lf->program_name == NULL ? "" : lf->program_name,
    lf->url == NULL ? "" : lf->url,
    lf->status == NULL ? "" : lf->status,
    lf->protocol == NULL ? "" : lf->protocol,
    lf->srcip == NULL ? "" : lf->srcip,

#ifdef LIBGEOIP_ENABLED
    (strlen(geoip_msg_src) == 0) ? "" : geoip_msg_src,
#else
    "",
#endif
    lf->srcport == NULL ? "" : lf->srcport,
    lf->dstip == NULL ? "" : lf->dstip,

#ifdef LIBGEOIP_ENABLED
    (strlen(geoip_msg_dst) == 0) ? "" : geoip_msg_dst,
#else
    "",
#endif
    lf->dstport == NULL ? "" : lf->dstport,
    lf->dstuser == NULL ? "" : lf->dstuser,
    lf->filename == NULL ? "" : lf->filename,
    lf->perm_before,
    lf->perm_after,
    lf->md5_before == NULL ? "" : lf->md5_before,
    lf->md5_after == NULL ? "" : lf->md5_after,
    lf->sha1_before == NULL ? "" : lf->sha1_before,
    lf->sha1_after == NULL ? "" : lf->sha1_after,
    lf->size_before == NULL ? "" : lf->size_before,
    lf->size_after == NULL ? "" : lf->size_after,
    lf->owner_before == NULL ? "" : lf->owner_before,
    lf->owner_after == NULL ? "" : lf->owner_after,
    lf->gowner_before == NULL ? "" : lf->gowner_before,
    lf->gowner_after == NULL ? "" : lf->gowner_after,
    lf->mtime_before == NULL ? "" : ctime(&lf->mtime_before),
    lf->mtime_after == NULL ? "" : ctime(&lf->mtime_after),
    lf->inode_before == NULL ? "" : lf->inode_before,
    lf->inode_after == NULL ? "" : lf->inode_after,
    lf->diff == NULL ? "" : lf->diff,
    lf->full_log == NULL ? "" : lf->full_log);

    // Dynamic fields, except for syscheck events
    if (lf->fields && !lf->filename) {
        for (i = 0; i < lf->nfields; i++) {
            if (lf->fields[i].value) {
                printf("%s: %s\n", lf->fields[i].key, lf->fields[i].value);
            }
        }
    }

    /* Print the last events if present */
    if (lf->generated_rule->last_events) {
        char **lasts = lf->generated_rule->last_events;
        while (*lasts) {
            printf("LastEvents: %.1256s\n", *lasts);
            lasts++;
        }
        lf->generated_rule->last_events[0] = NULL;
    }

    printf("-- END ALERT --\n");

    fflush(stdout);
    return;
}

void OS_Log(Eventinfo *lf)
{
    int i;

#ifdef LIBGEOIP_ENABLED
    if (Config.geoipdb_file) {
        if (lf->srcip && !lf->srcgeoip) {
            lf->srcgeoip = GetGeoInfobyIP(lf->srcip);
        }
        if (lf->dstip && !lf->dstgeoip) {
            lf->dstgeoip = GetGeoInfobyIP(lf->dstip);
        }
    }
#endif

    /* Writing to the alert log file */
fprintf(_aflog,
    "-- BEGIN ALERT --\n"
    "AlertId: %ld.%ld\n"
    "Group: %s\n"
    "Year: %d\n"
    "Month: %s\n"
    "Day: %02d\n"
    "Time: %s\n"
    "Hostname: %s\n"
    "Location: %s\n"
    "RuleId: %d\n"
    "FiredTimes: %d\n"
    "Level: %d\n"
    "Cve: %s\n"
    "Action: %s\n"
    "Comment: '%s'\n"
    "ProgramName: %s\n"
    "Url: %s\n"
    "Status: %s\n"
    "Protocol: %s\n"
    "SourceIp: %s\n"
    "SourceLocation: %s\n"
    "SourcePort: %s\n"
    "DestinationIp: %s\n"
    "DestLocation: %s\n"
    "DestPort: %s\n"
    "Username: %s\n"
    "Filename: %s\n"
    "PermBefore: %d\n"
    "PermAfter: %d\n"
    "Md5Before: %s\n"
    "Md5After: %s\n"
    "Sha1Before: %s\n"
    "Sha1After: %s\n"
    "SizeBefore: %s\n"
    "SizeAfter: %s\n"
    "OwnerBefore: %s\n"
    "OwnerAfter: %s\n"
    "GroupBefore: %s\n"
    "GroupAfter: %s\n"
    "DateBefore: %s\n"
    "DateAfter: %s\n"
    "InodeBefore: %ld\n"
    "InodeAfter: %ld\n"
    "Change: %s\n"
    "FullLog: %.1256s\n",
    (long int)lf->time,
    __crt_ftell,
    lf->generated_rule->group == NULL ? "" : lf->generated_rule->group,
    lf->year,
    lf->mon,
    lf->day,
    lf->hour,
    lf->hostname == NULL ? "" : lf->hostname,
    lf->location == NULL ? "" : lf->location,
    lf->generated_rule->sigid,
    lf->generated_rule->firedtimes,
    lf->generated_rule->level,
    lf->generated_rule->cve == NULL ? "" : lf->generated_rule->cve,
    lf->action == NULL ? "" : lf->action,
    lf->generated_rule->comment == NULL ? "" : lf->generated_rule->comment,
    lf->program_name == NULL ? "" : lf->program_name,
    lf->url == NULL ? "" : lf->url,
    lf->status == NULL ? "" : lf->status,
    lf->protocol == NULL ? "" : lf->protocol,
    lf->srcip == NULL ? "" : lf->srcip,

#ifdef LIBGEOIP_ENABLED
    (strlen(geoip_msg_src) == 0) ? "" : geoip_msg_src,
#else
    "",
#endif
    lf->srcport == NULL ? "" : lf->srcport,
    lf->dstip == NULL ? "" : lf->dstip,

#ifdef LIBGEOIP_ENABLED
    (strlen(geoip_msg_dst) == 0) ? "" : geoip_msg_dst,
#else
    "",
#endif
    lf->dstport == NULL ? "" : lf->dstport,
    lf->dstuser == NULL ? "" : lf->dstuser,
    lf->filename == NULL ? "" : lf->filename,
    lf->perm_before,
    lf->perm_after,
    lf->md5_before == NULL ? "" : lf->md5_before,
    lf->md5_after == NULL ? "" : lf->md5_after,
    lf->sha1_before == NULL ? "" : lf->sha1_before,
    lf->sha1_after == NULL ? "" : lf->sha1_after,
    lf->size_before == NULL ? "" : lf->size_before,
    lf->size_after == NULL ? "" : lf->size_after,
    lf->owner_before == NULL ? "" : lf->owner_before,
    lf->owner_after == NULL ? "" : lf->owner_after,
    lf->gowner_before == NULL ? "" : lf->gowner_before,
    lf->gowner_after == NULL ? "" : lf->gowner_after,
    lf->mtime_before == NULL ? "" : ctime(&lf->mtime_before),
    lf->mtime_after == NULL ? "" : ctime(&lf->mtime_after),
    lf->inode_before == NULL ? "" : lf->inode_before,
    lf->inode_after == NULL ? "" : lf->inode_after,
    lf->diff == NULL ? "" : lf->diff,
    lf->full_log == NULL ? "" : lf->full_log);

    // Dynamic fields, except for syscheck events
    if (lf->fields && !lf->filename) {
        for (i = 0; i < lf->nfields; i++) {
            if (lf->fields[i].value) {
                fprintf(_aflog, "%s: %s\n", lf->fields[i].key, lf->fields[i].value);
            }
        }
    }

    /* Print the last events if present */
    if (lf->generated_rule->last_events) {
        char **lasts = lf->generated_rule->last_events;
        while (*lasts) {
            fprintf(_aflog, "LastEvents: %.1256s\n", *lasts);
            lasts++;
        }
        lf->generated_rule->last_events[0] = NULL;
    }

    fprintf(_aflog, "-- END ALERT --\n");
    fflush(_aflog);

    return;
}

void OS_CustomLog(const Eventinfo *lf, const char *format)
{
    char *log;
    char *tmp_log;
    char tmp_buffer[1024];

    /* Replace all the tokens */
    os_strdup(format, log);

    snprintf(tmp_buffer, 1024, "%ld", (long int)lf->time);
    tmp_log = searchAndReplace(log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_TIMESTAMP], tmp_buffer);
    free(log);

    snprintf(tmp_buffer, 1024, "%ld", __crt_ftell);
    log = searchAndReplace(tmp_log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_FTELL], tmp_buffer);
    free(tmp_log);

    snprintf(tmp_buffer, 1024, "%s", (lf->generated_rule->alert_opts & DO_MAILALERT) ? "mail " : "");
    tmp_log = searchAndReplace(log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_RULE_ALERT_OPTIONS], tmp_buffer);
    free(log);

    snprintf(tmp_buffer, 1024, "%s", lf->hostname ? lf->hostname : "None");
    log = searchAndReplace(tmp_log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_HOSTNAME], tmp_buffer);
    free(tmp_log);

    snprintf(tmp_buffer, 1024, "%s", lf->location ? lf->location : "None");
    tmp_log = searchAndReplace(log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_LOCATION], tmp_buffer);
    free(log);

    snprintf(tmp_buffer, 1024, "%d", lf->generated_rule->sigid);
    log = searchAndReplace(tmp_log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_RULE_ID], tmp_buffer);
    free(tmp_log);

    snprintf(tmp_buffer, 1024, "%d", lf->generated_rule->level);
    tmp_log = searchAndReplace(log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_RULE_LEVEL], tmp_buffer);
    free(log);

    snprintf(tmp_buffer, 1024, "%s", lf->srcip ? lf->srcip : "None");
    log = searchAndReplace(tmp_log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_SRC_IP], tmp_buffer);
    free(tmp_log);

    snprintf(tmp_buffer, 1024, "%s", lf->dstuser ? lf->dstuser : "None");

    tmp_log = searchAndReplace(log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_DST_USER], tmp_buffer);
    free(log);

    char *escaped_log;
    escaped_log = escape_newlines(lf->full_log);

    log = searchAndReplace(tmp_log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_FULL_LOG], escaped_log );
    free(tmp_log);
    free(escaped_log);

    snprintf(tmp_buffer, 1024, "%s", lf->comment ? lf->comment : "");
    tmp_log = searchAndReplace(log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_RULE_COMMENT], tmp_buffer);
    free(log);

    snprintf(tmp_buffer, 1024, "%s", lf->generated_rule->group ? lf->generated_rule->group : "");
    log = searchAndReplace(tmp_log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_RULE_GROUP], tmp_buffer);
    free(tmp_log);

    fprintf(_aflog, "%s", log);
    fprintf(_aflog, "\n");
    fflush(_aflog);

    free(log);

    return;
}

void OS_InitFwLog()
{
    /* Initialize fw log regexes */
    if (!OSMatch_Compile(FWDROP, &FWDROPpm, 0)) {
        ErrorExit(REGEX_COMPILE, ARGV0, FWDROP,
                  FWDROPpm.error);
    }

    if (!OSMatch_Compile(FWALLOW, &FWALLOWpm, 0)) {
        ErrorExit(REGEX_COMPILE, ARGV0, FWALLOW,
                  FWALLOWpm.error);
    }
}

int FW_Log(Eventinfo *lf)
{
    /* If we don't have the srcip or the
     * action, there is no point in going
     * forward over here
     */
    if (!lf->action || !lf->srcip || !lf->dstip || !lf->srcport ||
            !lf->dstport || !lf->protocol) {
        return (0);
    }

    /* Set the actions */
    switch (*lf->action) {
        /* discard, drop, deny, */
        case 'd':
        case 'D':
        /* reject, */
        case 'r':
        case 'R':
        /* block */
        case 'b':
        case 'B':
            os_free(lf->action);
            os_strdup("DROP", lf->action);
            break;
        /* Closed */
        case 'c':
        case 'C':
        /* Teardown */
        case 't':
        case 'T':
            os_free(lf->action);
            os_strdup("CLOSED", lf->action);
            break;
        /* allow, accept, */
        case 'a':
        case 'A':
        /* pass/permitted */
        case 'p':
        case 'P':
        /* open */
        case 'o':
        case 'O':
            os_free(lf->action);
            os_strdup("ALLOW", lf->action);
            break;
        default:
            if (OSMatch_Execute(lf->action, strlen(lf->action), &FWDROPpm)) {
                os_free(lf->action);
                os_strdup("DROP", lf->action);
            }
            if (OSMatch_Execute(lf->action, strlen(lf->action), &FWALLOWpm)) {
                os_free(lf->action);
                os_strdup("ALLOW", lf->action);
            } else {
                os_free(lf->action);
                os_strdup("UNKNOWN", lf->action);
            }
            break;
    }

    /* Log to file */
    fprintf(_fflog,
            "%d %s %02d %s %s%s%s %s %s %s:%s->%s:%s\n",
            lf->year,
            lf->mon,
            lf->day,
            lf->hour,
            lf->hostname != lf->location ? lf->hostname : "",
            lf->hostname != lf->location ? "->" : "",
            lf->location,
            lf->action,
            lf->protocol,
            lf->srcip,
            lf->srcport,
            lf->dstip,
            lf->dstport);

    fflush(_fflog);

    return (1);
}
