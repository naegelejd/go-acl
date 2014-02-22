#include <sys/types.h>
#include <sys/acl.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    char *filename = argv[1];

    acl_t acl = acl_get_file(filename, ACL_TYPE_EXTENDED);
    if (!acl) {
        fprintf(stderr, "Failed to obtain ACL from %s\n", filename);
    }

    char *acl_text = acl_to_text(acl, NULL);
    if (!acl_text) {
        fprintf(stderr, "Failed to convert ACL to text\n");
        return EXIT_FAILURE;
    }

    printf("%s\n", acl_text);
    acl_free(acl_text);

    acl_free(acl_text);

    return EXIT_SUCCESS;
}
