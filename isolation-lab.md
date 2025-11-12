# Lab: Process Memory Isolation on Linux

## Objectives

By completing this lab, you will be able to:

*   Understand the fundamental security principle of process memory isolation in Linux.
*   Demonstrate that a process cannot directly read the memory of another process using standard file I/O on `/proc/[PID]/mem`.
*   Explain *why* the kernel blocks this direct access.
*   Contrast the failed direct access with successful, sanctioned methods for inspecting process memory, such as using a debugger (`gdb`) or the `process_vm_readv` system call.

## Environment Preparation

This lab requires a Linux environment with the following tools installed:

*   A C compiler, such as `gcc`.
*   The GNU Debugger, `gdb`.
*   A terminal with `sudo` (root) privileges, as some commands require elevated permissions.

You can typically install these tools on Debian/Ubuntu-based systems with:

```bash
sudo apt update
sudo apt install build-essential gdb
```

On RHEL/CentOS/Fedora systems:

```bash
sudo dnf groupinstall "Development Tools"
sudo dnf install gdb
```

## Background: The Core Concept

In modern operating systems, one of the most critical security features is **memory isolation**. Each process operates in its own virtual address space, preventing it from interfering with or spying on other processes.

The `/proc` filesystem provides a window into the kernel's inner workings. For any running process with a Process ID (PID), there is a corresponding directory at `/proc/[PID]/`. Inside this directory, a special file named `mem` theoretically represents the process's entire virtual memory.

However, the kernel strictly guards access to this file. You cannot simply use a command like `cat` or `dd` to read another process's memory. The primary reason for this is security: if any process could read another's memory, it could trivially steal passwords, encryption keys, and other sensitive data.

This lab will prove this restriction exists and then show the correct, privileged ways to access memory when necessary (e.g., for debugging).

---

## Part 1: The Failed Attempt (Demonstrating Isolation)

In this part, we will create a target process with a "secret" in its memory and then attempt to read that secret from another terminal.

### Step 1: Create the Target Process

Create a file named `target.c` with the following content. This program initializes a global string, prints its own PID and the memory address of the string, and then loops forever.

```c
// target.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// A "secret" stored in the program's data segment
char secret[] = "This is the secret data in memory!";

int main() {
    printf("Target Process Started.\n");
    printf("PID: %d\n", getpid());
    printf("Address of 'secret': %p\n", secret);
    printf("Value of 'secret': %s\n", secret);

    // Loop forever to keep the process running
    while (1) {
        sleep(1);
    }

    return 0;
}
```

### Step 2: Compile and Run the Target Process

Open a terminal and compile the C code.

```bash
gcc -o target target.c
```

Now, run the compiled program in the background using the `&` symbol. This allows you to continue using the same terminal.

```bash
./target &
```

You will see output similar to this. **Note the PID and the Address**—you will need them for the next steps.

```
Target Process Started.
PID: 28541
Address of 'secret': 0x55b8b8b56004
Value of 'secret': This is the secret data in memory!
```

For the rest of this guide, we will use `PID=28541` and `ADDRESS=0x55b8b8b56004`. **Remember to replace these with the values from your own terminal.**

### Step 3: Attempt to Read the Memory (The Failure)

Now, let's try to read the memory of our target process using standard file-reading tools.

#### Attempt 1: Using `cat`

This is the most naive attempt. We'll try to read the entire memory file.

```bash
# Replace 28541 with your target's PID
sudo cat /proc/28541/mem
```

**Expected Output:**

```
cat: /proc/28541/mem: Input/output error
```

**Why it fails:** The kernel denies the read operation. The `mem` file is not a regular file you can stream from top to bottom. It's a representation of a virtual address space, and the kernel's security check (`ptrace_may_access`) prevents this kind of direct access.

#### Attempt 2: Using `dd` to Read a Specific Address

This is a more sophisticated attempt. We know the address of our secret, so we can use `dd` to try and read from that specific offset.

```bash
# Replace 28541 with your values
OFFSET=$((16#804a040))
sudo dd if=/proc/28541/mem bs=1 skip=$OFFSET count=40
```

**Expected Output:**

```
dd: error reading '/proc/28541/mem': Input/output error
0+0 records in
0+0 records out
0 bytes copied, 0.000123456 s, 0.0 kB/s
```

**Why it fails:** Even though we specified an offset, the kernel's security check still blocks the operation. The process reading the memory (`dd`) does not have the proper "tracing" relationship with the target process, so the access is denied. This successfully demonstrates the memory isolation you wanted to see.

---

## Part 2: The Correct Way (Bypassing Isolation Sanely)

To show that the memory *is* accessible through the proper, sanctioned channels, let's use tools that are designed for this purpose. This proves the restriction is about permissions, not a technical impossibility.

### Method 1: Using a Debugger (`gdb`)

The GNU Debugger (`gdb`) uses the `ptrace` system call, which is the kernel-approved way for one process to inspect and control another.

1.  Attach `gdb` to the running target process:
    ```bash
    # Replace 28541 with your target's PID
    sudo gdb -p 28541
    ```

2.  `gdb` will pause the target process. You can now inspect its memory. Use the `x` (examine) command to read the string at the address we found earlier.
    ```gdb
    (gdb) x/s 0x55b8b8b56004
    ```

3.  **Expected Output:**
    ```
    0x55b8b8b56004: "This is the secret data in memory!"
    ```
    Success! `gdb` was able to read the memory because it first attached to the process using `ptrace`, which grants it the necessary permissions from the kernel.

4.  Detach and exit `gdb` to let the target process continue:
    ```gdb
    (gdb) detach
    (gdb) quit
    ```

### Method 2: Using a Dedicated System Call (`process_vm_readv`)

Modern Linux provides a more direct system call, `process_vm_readv`, specifically for reading memory from another process. It still requires the same permissions.

1.  Create a file named `reader.c` with the following content:

    ```c
    // reader.c
    #define _GNU_SOURCE
    #include <stdio.h>
    #include <stdlib.h>
    #include <sys/uio.h>
    #include <errno.h>

    int main(int argc, char *argv[]) {
        if (argc != 4) {
            fprintf(stderr, "Usage: %s <pid> <address_in_hex> <length>\n", argv[0]);
            return 1;
        }

        pid_t pid = atoi(argv[1]);
        unsigned long long address = strtoull(argv[2], NULL, 16);
        size_t len = atoi(argv[3]);

        char buf[len + 1];

        struct iovec local[1];
        struct iovec remote[1];

        local[0].iov_base = buf;
        local[0].iov_len = len;
        remote[0].iov_base = (void *)address;
        remote[0].iov_len = len;

        ssize_t nread = process_vm_readv(pid, local, 1, remote, 1, 0);
        if (nread == -1) {
            perror("process_vm_readv");
            // If you get "Operation not permitted", it's the expected security block.
            // Run with sudo to allow it.
            return 1;
        }

        buf[nread] = '\0'; // Null-terminate for printing
        printf("Read %zd bytes from PID %d at address %llx:\n", nread, pid, address);
        printf("%s\n", buf);

        return 0;
    }
    ```

2.  Compile and run it:
    ```bash
    gcc -o reader reader.c

    # Replace PID, address, and length with your values.
    # The length of "This is the secret data in memory!" is 34 characters.
    sudo ./reader 28541 55b8b8b56004 34
    ```

3.  **Expected Output:**
    ```
    Read 34 bytes from PID 28541 at address 55b8b8b56004:
    This is the secret data in memory!
    ```

---

## Conclusion

This lab has demonstrated a cornerstone of Linux security: **process memory isolation**.

| Method | Command | Result | Why? |
| :--- | :--- | :--- | :--- |
| **Direct Read (Your Request)** | `sudo cat /proc/PID/mem` | **FAILS** | Kernel security prevents untraced access. The `mem` file is not a simple stream. |
| **Direct Read with Offset** | `sudo dd if=/proc/PID/mem ...` | **FAILS** | Even with a specific offset, the `ptrace_may_access` check blocks the read. |
| **Correct Method (Debugger)** | `sudo gdb -p PID` | **SUCCEEDS** | `gdb` uses `ptrace` to attach, which is the sanctioned way to inspect a process. |
| **Correct Method (System Call)** | `sudo ./reader PID ...` | **SUCCEEDS** | `process_vm_readv` is the modern, efficient API for this, but it still requires elevated privileges. |

You have successfully shown that you cannot simply "peek" into a running process's memory from another one using standard file I/O. The kernel enforces this isolation as a fundamental security measure. Access is possible, but only through explicit, privileged, and kernel-sanctioned interfaces like `ptrace` or `process_vm_readv`.

## Cleanup

Don't forget to stop the background `target` process. You can do this by bringing it to the foreground with `fg` and pressing `Ctrl+C`, or by killing it using its PID.

```bash
# Using the PID from our example
kill 28541
```