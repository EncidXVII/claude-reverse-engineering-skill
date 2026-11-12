# Crackme fixture (evals.json case 1)

Save the code below as `crackme.c` in an empty directory, then build it:

```bash
cc -O1 -o crackme crackme.c && strip crackme
```

The password is XOR-encoded so `strings` alone does not reveal it.
Expected answer: password `r3v3rs3d`, flag printed on success.
Give the agent only the built binary, not this file.

```c
#include <stdio.h>
#include <string.h>

static const unsigned char enc[] = {0x38, 0x79, 0x3c, 0x79, 0x38, 0x39, 0x79, 0x2e};

static int check(const char *s)
{
    size_t i;
    if (strlen(s) != sizeof enc)
        return 0;
    for (i = 0; i < sizeof enc; i++)
        if ((unsigned char)(s[i] ^ 0x4a) != enc[i])
            return 0;
    return 1;
}

int main(void)
{
    char buf[64];
    printf("password: ");
    if (!fgets(buf, sizeof buf, stdin))
        return 1;
    buf[strcspn(buf, "\n")] = '\0';
    if (check(buf)) {
        puts("flag{x0r_is_n0t_crypt0}");
        return 0;
    }
    puts("nope");
    return 1;
}
```
