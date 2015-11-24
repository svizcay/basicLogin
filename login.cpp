#include <string.h>
#include <iostream>

#include <unistd.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <pwd.h>					// getpwnam()
#include <shadow.h>					// getspnam()
#include <exception>

// Define custom PAM conversation function
int custom_converation(int num_msg, const struct pam_message** msg, struct pam_response** resp, void* appdata_ptr)
{
    // Provide password for the PAM conversation response that was passed into appdata_ptr
    struct pam_response* reply = (struct pam_response* )malloc(sizeof(struct pam_response));
    reply[0].resp = (char*)appdata_ptr;
    reply[0].resp_retcode = 0;

    *resp = reply;

    return PAM_SUCCESS;
}

int main (int argc, char* argv[]) 
{
    if (argc > 2) {
        // Set up a custom PAM conversation passing in authentication password
        char* password = (char*)malloc(strlen(argv[2]) + 1);
        strcpy(password, argv[2]);        
        struct pam_conv pamc = { custom_converation, password };
        pam_handle_t* pamh; 
        int retval;

		struct passwd *info = getpwnam(argv[1]);
		std::cout << "id: " << info->pw_uid << std::endl;
		std::cout << "gid: " << info->pw_gid << std::endl;
		std::cout << "pass: " << info->pw_passwd << std::endl;

		try {
			struct spwd *info2 = getspnam(argv[1]);
			std::cout << "encrypted: " << info2->sp_pwdp << std::endl;
		} catch (std::exception & e) {
			std::cout << "couldn't retrieve hashed password" << std::endl;
		}

        // Start PAM - just associate with something simple like the "whoami" command
        if ((retval = pam_start("whoami", argv[1], &pamc, &pamh)) == PAM_SUCCESS)
        {
            // Authenticate the user
            if ((retval = pam_authenticate(pamh, 0)) == PAM_SUCCESS) {
                fprintf(stdout, "OK\n");
				system("id");

			} else {
                fprintf(stderr, "FAIL: pam_authentication failed.\n"); 
			}

            // All done
            pam_end(pamh, 0); 
            return retval; 
        }
        else
        {
            fprintf(stderr, "FAIL: pam_start failed.\n"); 
            return retval;
        }
    }

    fprintf(stderr, "FAIL: expected two arguments for user name and password.\n"); 
    return 1; 
}
