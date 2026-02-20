# Advanced Configuration

In this section, we will get acquainted with classifying different security modes.
We strongly recommend using **mTLS mode**; however, since mTLS setup steps include all One-Way TLS steps, we will first explain One-Way TLS.
Therefore, if you intend to implement mTLS, first perform One-Way TLS steps and then follow the mTLS section.

---

## 1. One-Way TLS Configuration (Like HTTPS)

In this mode, the server has a private key, and the client ensures connection integrity by having the server's public key.

### Step 1: Create Server Key
Run the following command on the server (VPS):

```bash
./phoenix-server -gen-keys
```

The output of this command includes two items:
1.  A file named `private.key` is created in the same folder.
2.  A **Public Key** is printed in the terminal output. **Copy and save it.**

Then, to match the default configuration file, rename the private key file:
```bash
mv private.key server.private.key
```

### Step 2: Configure Server (`server.toml`)
Open `server.toml` and uncomment the `private_key` line (by removing `#`):

```toml
[security]
# ...
private_key = "server.private.key"
```

### Step 3: Configure Client (`client.toml`)
On your computer, open `client.toml`. Find the `server_public_key` variable, uncomment it, and set its value to the **Server Public Key** (which you saved in Step 1):

```toml
server_public_key = "YOUR_SERVER_PUBLIC_KEY..."
```

**Congratulations!** Now One-Way TLS mode is activated and you can use the program.

---

## 2. mTLS Configuration (Mutual Authentication - Recommended)

For maximum security (Anti-Probing), after performing the above steps (One-Way TLS), perform the following steps as well.

### Step 4: Create Client Key
Run the following command on your computer (Client side):

```bash
./phoenix-client -gen-keys
# Or in Windows:
# .\phoenix-client.exe -gen-keys
```

The output is like before:
1.  The `private.key` file is created.
2.  A **Public Key** is shown to you. **Copy and save it.**

Rename the private key file:
```bash
mv private.key client.private.key
# Or in Windows (PowerShell):
# Rename-Item private.key client.private.key
```

### Step 5: Configure Client (`client.toml`)
Open `client.toml` and uncomment the `private_key` line:

```toml
# Path to client private key you just created
private_key = "client.private.key"
```

### Step 6: Configure Server (`server.toml`)
Return to the server and open `server.toml`.
Uncomment the `authorized_clients` variable (list of authorized clients) and put the Client Public Key (which you got in Step 4) inside it:

```toml
[security]
# ...
authorized_clients = [
  "CLIENT_PUBLIC_KEY..."
]
```

**Finished!** Now just run the server and client. In this mode, only your client is allowed to connect to the server.

::: tip Important Note on File Names
In all the steps above, we used the `mv` command (rename) to change the names of created `private.key` files to `server.private.key` and `client.private.key` to match the default configuration files (`server.toml` and `client.toml`).
If you do not want to change the file names, you must edit the value of the `private_key` variable in the configuration files and enter your file address/name.
:::

::: tip Return to Execution
Now that you have enabled at least one of the security modes, you can return to the previous page (**Installation and Setup**) and by reading the **Executing the Application** section, run your service with peace of mind.
:::
