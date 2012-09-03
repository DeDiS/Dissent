#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char **argv)
{
  unsigned long ept;

  if (argc != 2) {
    fprintf(stderr, "Usage: timeconvert epochtime\n");
    exit(1);
  }

  if (sscanf(argv[1], "%lu", &ept) != 1) {
    fprintf(stderr, "Usage: timeconvert epochtime\n");
    exit(1);
  }
  
  fprintf(stdout, "%s\n", ctime((time_t *) &ept));
  exit(0);
}
