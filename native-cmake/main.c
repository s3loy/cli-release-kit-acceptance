#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--version") == 0) {
    puts(APP_NAME " " APP_VERSION);
    return 0;
  }
  if (argc == 3 && strcmp(argv[1], "--echo") == 0) {
    puts(argv[2]);
    return strcmp(argv[2], "packaged-checked") == 0 ? 0 : 1;
  }
  if (argc == 2 && strcmp(argv[1], "--preset-check") == 0) {
    puts(PRESET_MESSAGE);
    return 0;
  }
  fputs("usage: --version | --echo MESSAGE | --preset-check\n", stderr);
  return 2;
}
