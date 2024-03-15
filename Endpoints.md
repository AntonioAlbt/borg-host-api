# List of all endpoints

- /auth/login = create new login token, data: `{ login: string, pw: string, appname: string }`

All other endpoints require authentication with the header `Authorization: Bearer <token>`:

- /auth/check = check token, returns token information
- /get/admin/all-mounts = get all current mounts of all users
- /get/mounts = get the mounts of the current user
- /do/mount = mount new borg repo, data: `{ repo: string, passphrase: string }` - `repo` = borg repo url, e.g. `ssh://user@host/path/to/repo`, returns repo mount path
- /do/umount = umount borg repo, data: `{ path: string }`
- /access/[repo-path]/[file-path-in-repo] = access a file or directory in mounted path, returns file listing for dir or file content (default: base64 gzip in json) for files
  - optional params for file view: `?text` - return content in json as text, `?download` - return plain file content, `?gzip` - return only gzip-ed content
  - request with OPTIONS method to get stat info of path

- mounts timeout after 5 minutes after last usage (see /get/mounts output)
