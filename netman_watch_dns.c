#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <systemd/sd-bus.h>

/* Dbus settings to get the DNS entries updated in resolv.conf */
const char *bus_name = "org.openbmc.NetworkManager";
const char *object_path = "/org/openbmc/NetworkManager/Interface";
const char *intf_name = "org.openbmc.NetworkManager";

/* Used to tell Network Manager that Name Server listing is coming from DHCP */
const char *DHCP_MARKER = "DHCP_AUTO= ";

#define DHCP_MARKER_LEN strlen(DHCP_MARKER)

/*
 * ----------------------------------------------
 *  Receives the buffer that has the IPs of DNS
 *  and then makes a dbus call to have these DNS
 *  entries updated in /etc/resolv.conf
 *  --------------------------------------------
 */
int update_resolv_conf(const char *dns_entry)
{
    /* To read the message sent by dbus handler */
    const char *resp_msg = NULL;

    /* Generic error handler */
    int rc = 0;

    if(dns_entry == NULL || !(strlen(dns_entry)))
    {
        fprintf(stderr,"Invalid DNS entry\n");
        return -1;
    }

    /*
     * Since 'state' file gets touched many a times during the network setting,
     * it does not make sense to  have the same DNS entry updated in
     * resolv.conf. SO we can actually have a cache of what was previously
     * updated and not update if the same DNS info is supplied again.
     * Eventhough this approach is a gain performance wise, it will
     * open up windows. Assume a case where DHCP has given 1.2.3.4 as IP and
     * user goes and updates the DNS as 4.5.6.7 and then user restarts the
     * network and thus getting the value of 1.2.3.4. If we maintain a cache of
     * what was previously updated, since we get 1.2.3.4 again, we will not
     * update with 1.2.3.4 eventhough that is needed since 4.5.6.7 would not
     * make sense. So doing updates to resolv.conf each time is bit of a
     * overkill but its error proof.
     */

    /* Encapsulated respose by dbus handler */
    sd_bus_message *response = NULL;

    /* Errors reported by dbus handler */
    sd_bus_error bus_error = SD_BUS_ERROR_NULL;

    /*
     * Gets a hook onto SYSTEM bus. This API may get called multiple
     * times so do not want to have so many instances of bus as it
     * leads to system resource issues. Re use the one that is present.
     */
    static sd_bus *bus_type = NULL;
    if(bus_type == NULL)
    {
        rc = sd_bus_open_system(&bus_type);
        if(rc < 0)
        {
            fprintf(stderr,"Error:[%s] getting system bus\n",strerror(-rc));
            return rc;
        }
    }

    rc = sd_bus_call_method(
                            bus_type,        /* In the System Bus */
                            bus_name,        /* Service to contact */
                            object_path,     /* Object path */
                            intf_name,       /* Interface name */
                            "SetNameServers",/* Method to be called */
                            &bus_error,      /* object to return error */
                            &response,       /* Response buffer if any */
                            "s",             /* Input as strings */
                            dns_entry,       /* string of DNS IPs */
                            NULL);           /* No return message expected */
    if(rc < 0)
    {
        fprintf(stderr,"ERROR updating DNS entries:[%s]\n",bus_error.message);
        goto finish;
    }

    /* Extract the encapsulated response message */
    rc = sd_bus_message_read(response, "s", &resp_msg);
    if (rc < 0)
    {
        fprintf(stderr,"Error:[%s] reading dns"
                " updation status\n",strerror(-rc));
    }
    else
    {
        printf("%s\n",resp_msg);
    }

finish:
    sd_bus_error_free(&bus_error);
    response = sd_bus_message_unref(response);

    return rc;
}

/*
 * ----------------------------------------------
 *  Gets invoked by inotify handler whenever the
 *  netif/state file gets modified
 *  -or- when this binary first gets launched.
 *  --------------------------------------------
 */
int read_netif_state_file(const char *netif_dir, const char *state_file)
{
    FILE *fp;

    /* Each line read from 'state' file */
    char *line = NULL;

    /* A list containing all the DNS IPs that are mentioned in 'state' file. */
    char *dns_list = NULL;

    /* length of each line read from 'state' file */
    size_t len = 0;

    /* Length of current and updated dns list */
    size_t list_len = 0;
    size_t new_list_len = 0;

    /* Generic error reporter */
    int rc = 0;

    /* Extract the 'state' file */
    char netif_state_file[strlen(netif_dir) + strlen(state_file) + 2];
    sprintf(netif_state_file,"%s%s", netif_dir,state_file);

    fp = fopen(netif_state_file,"r");
    if(fp == NULL)
    {
        fprintf(stderr,"Error opening[%s]\n",netif_state_file);
        return -1;
    }

    /*
     * Read the file line by line and look for the one that starts with DNS
     * If there is one, then what appears after DNS= are the IPs of the DNS
     * Just checking for DNS here since any non standard IP is rejected by
     * the dbus handler. This is to cater to cases where file may have DNS =
     */
    while ((getline(&line, &len, fp)) != -1)
    {
        if(!(strncmp(line,"DNS",3)))
        {
            /* Go all the way until the start of IPs */
            char *dns_entry = strrchr(line, '=');

            /* Advance to the first character after = */
            dns_entry = &((char *)dns_entry)[1];

            /* If we have never populated anything into the list */
            if(dns_list == NULL)
            {
                /* The extra 2 characters to leave some gaps between DNS
                 * entries that would come from multiple lines since each line
                 * would start with DNS= and this overlaps with previous DNS IP.
                 * Although I don't see this as any reality to have DNS IPs
                 * spreading multiple lines.
                 */
                list_len = strlen(dns_entry) + DHCP_MARKER_LEN + 2;
                dns_list = (char *)malloc(list_len);

                /*
                 * Populate DHCP_AUTO= along with the first line of DNS entries
                 * This will help in putting the appropriate comments in
                 * /etc/resolv.conf indicating the mode of DNS setting.
                 */
                memset(dns_list, ' ', list_len);
                memcpy(dns_list, DHCP_MARKER, DHCP_MARKER_LEN);
                memcpy(&dns_list[DHCP_MARKER_LEN], dns_entry, strlen(dns_entry));
                dns_list[list_len]='\0';
            }
            else
            {
                /* This would be the entries that are coming from second+ line */
                new_list_len = strlen(dns_entry) + list_len + 2;
                dns_list = (char *)realloc(dns_list, new_list_len);

                memset(&dns_list[list_len], ' ', strlen(dns_entry) + 2);
                memmove(&dns_list[list_len], dns_entry, strlen(dns_entry));

                /* Starting offset for next line */
                list_len = new_list_len;
                dns_list[list_len] = '\0';
            }
        }

        /* Memory is allocated by getline and user needs to free */
        if(line)
        {
            free(line);
            line = NULL;
        }
    }

    /* If we have found some or more DNS entries */
    if(dns_list)
    {
        /*
         * Being extra cautious if string somehow is not null terminated in the loop
         */
        dns_list[list_len] = '\0';

        rc = update_resolv_conf(dns_list);
        if(rc < 0)
        {
            fprintf(stderr,"Error updating resolv.conf with:[%s]\n",dns_list);
        }

        free(dns_list);
        dns_list = NULL;
    }

    return 0;
}

void usage(void)
{
    printf("Usage: netman_watch_dns <Absolute path of DHCP netif state file>\n"
            "Example: netman_watch_dns /run/systemd/netif/state\n");
    return;
}

/*
 * ------------------------------------------------------
 *  Registers a inotify watch on the state file and calls
 *  into handling the state file whenever there is a change.
 * ------------------------------------------------------
 */
int watch_for_dns_change(char *netif_dir, char *state_file)
{
    int inotify_fd, wd;

    /* the aligned statement below is per the recommendation by inotify(7) */
    char event_data[4096]
        __attribute__ ((aligned(__alignof__(struct inotify_event))));

    /* To check the number of bytes read from inotify event */
    ssize_t bytes_read = 0;

    /* To walk event by event when inotify returns */
    char *ptr = NULL;

    /* Variable to hold individual event notification */
    const struct inotify_event *event = NULL;

    /* Generic error handler */
    int rc = 0;

    /* Create inotify instance */
    inotify_fd = inotify_init();
    if(inotify_fd == -1)
    {
        fprintf(stderr,"Error:[%s] initializing Inotify",strerror(errno));
        return -1;
    }

    /* Register to write actions on the netif directory */
    wd = inotify_add_watch(inotify_fd, netif_dir, IN_MODIFY);
    if(wd == -1)
    {
        fprintf(stderr,"Error:[%s] adding watch for:[%s]\n",
                strerror(errno), netif_dir);
        return -1;
    }

    /*
     * When this is first launched, we need to go see
     * if there is anything present in the state file.
     * Doing it here to close any gaps between the file
     * getting created before registering inotifier.
     */
    rc = read_netif_state_file(netif_dir, state_file);
    if(rc < 0)
    {
        fprintf(stderr,"Error doing initial processing of state file\n");
    }

    /* Read events forever */
    for (;;)
    {
        memset(event_data, 0x0, sizeof(event_data));
        bytes_read = read(inotify_fd, event_data, sizeof(event_data));
        if(bytes_read <= 0)
        {
            fprintf(stderr,"event_data read from inotify fd was Invalid\n");
            continue;
        }

        /* Process all of the events in buffer returned by read() */
        for(ptr = event_data; ptr < event_data + bytes_read;
            ptr += sizeof(struct inotify_event) + event->len)
        {
            event = (struct inotify_event *)ptr;

            /*
             * We are not interested in anything other than updates to
             * state file. Now when this code is being written, its in
             * /run/systemd/netif/state.
             */
            if((event->len > 0) && (strstr(event->name, state_file)))
            {
                rc = read_netif_state_file(netif_dir, state_file);
                if(rc < 0)
                {
                    fprintf(stderr,"Error processing inotify event\n");
                }
            }
        } /* Processing all inotify events. */
    } /* Endless loop waiting for events. */

    /*
     * Technically, we should not reach here since the monitor function
     * is not supposed to stop even on error. But for completeness.....
     */
    inotify_rm_watch(inotify_fd, wd);
    close(inotify_fd);

    return 0;
}

int main(int argc, char *argv[])
{
    /* Generic error handler */
    int rc = 0;

    /* Sanity checking */
    if(argc != 2 || argv[1] == NULL)
    {
        usage();
        return -1;
    }

    /*
     * We now have the job of extracting the directory and
     * the state file from the user supplied input.
     */
    char netif_dir[strlen(argv[1]) + 1];
    memset(netif_dir, 0x0, sizeof(netif_dir));

    /* File where the actual DNS= entry is found */
    char *state_file = NULL;

    /* Filter invalid inputs */
    state_file = strrchr(argv[1], '/');
    if(strlen(state_file) <= 1)
    {
        fprintf(stderr,"Invalid state file :[%s] specified\n",state_file);
        return -1;
    }
    else
    {
        /* we have /state now and what we need is just the 'state' */
        state_file = &((char *)state_file)[1];

        /*
         * Also extract the Absolute Path of the directory
         * containing this state file
         */
        strncpy(netif_dir, argv[1], strlen(argv[1]) - strlen(state_file));
        strcat(netif_dir,"\0");
    }

    printf("Watching for changes in DNS settings..\n");

    /* Now that we have checked it once. rest is all notification bases. */
    rc = watch_for_dns_change(netif_dir, state_file);
    if(rc < 0)
    {
        fprintf(stderr,"Error watching for DNS changes\n");
    }

    return 0;
}
