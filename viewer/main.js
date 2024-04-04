const { createApp } = Vue
const { createVuetify } = Vuetify

const vuetify = createVuetify()

createApp({
    data() {
        return {
            account: null,
            loginModel: { login: "", pw: "" },
            loadingLogin: false,
            loginError: null,
            showConfirm2FADialog: false,
            tempToken: null,
            selected2FAMethod: null,
            input2FACode: "",

            currentMounts: [],
            secureMountData: [],
            currentPath: "~",
            showAddRepoDataDialog: false,
            showCreateMountDialog: false,
            repoModel: { url: "", pp: "" },
            loadingCurrentPathData: false,
            currentPathData: null,
            selectedRepoInfoToMount: null,
            loadingMounting: false,
            showFileContentDialog: false,
            selectedFileToShow: null,
            selectedFileContent: null,
            downloadingFiles: [],
            passkeys: [],
            show2FACodeDialog: false,
            known2FACodeData: null,
        }
    },
    mounted() {
        this.account = window.localStorage.getItem("account") != null ? JSON.parse(window.localStorage.getItem("account")) : null
        this.secureMountData = window.localStorage.getItem("secure-mount-data") != null ? JSON.parse(window.localStorage.getItem("secure-mount-data")) : []

        const func = () => {
            if (this.account == null) return
            this.updateMounts()
        };
        setInterval(func, 30 * 1000)

        if (this.account && this.account.token) {
            this.authedFetch("/auth/check").then((data) => {
                if (data.error) {
                    window.localStorage.setItem("account", "null")
                    this.account = null
                } else {
                    func()
                    this.authedFetch("/get/passkeys").then((data) => {
                        if (!data.error) {
                            this.passkeys = data.passkeys
                        } else {
                            this.passkeys = []
                        }
                    })
                }
            })
        }
    },
    methods: {
        updateMounts() {
            this.authedFetch("/get/mounts").then((data) => {
                if (!data.error) {
                    this.currentMounts = data.mounts
                } else {
                    this.currentMounts = []
                }
            })
        },
        updatePasskeys() {
            this.authedFetch("/get/passkeys").then((data) => {
                if (!data.error) {
                    this.passkeys = data.passkeys
                } else {
                    this.passkeys = []
                }
            })
        },
        handleLoginClick() {
            this.loadingLogin = true;
            fetch("/auth/login", { method: "POST", body: JSON.stringify({ ...this.loginModel, appname: "BorgRepoViewer-Web" }) })
                .then((res) => res.json()).then((json) => {
                    // console.log(json)
                    if (json.error) {
                        this.loginError = json.error
                        return
                    } else if (json.token) {
                        this.account = { login: this.loginModel.login, token: json.token }
                        window.localStorage.setItem("account", JSON.stringify(this.account))
                    } else if (json["2fa"]) {
                        this.showConfirm2FADialog = true;
                        this.tempToken = json.tempToken;
                    }
                }).then((_) => this.loadingLogin = false).catch((err) => {
                    this.loadingLogin = false
                    this.loginError = JSON.stringify(err)
                }).then((_) => {
                    if (!this.account) return;
                    return this.updateMounts()
                })
        },
        handleLogoutClick() {
            this.loadingLogin = true;
            this.authedFetch("/auth/remove-token")
                .then((_) => {
                    this.account = null
                    window.localStorage.setItem("account", "null")
                }).then((_) => this.loadingLogin = false).catch((err) => {this.loadingLogin = false; console.error(err)})
        },
        handleAddRepoDataDialogSave() {
            this.secureMountData.push({ repo: this.repoModel.url, passphrase: this.repoModel.pp })
            window.localStorage.setItem("secure-mount-data", JSON.stringify(this.secureMountData))
            this.showAddRepoDataDialog = false
        },
        setCurrentPath(path) {
            this.currentPath = path
            this.currentPathData = null
            if (path == "~") {
                this.loadingCurrentPathData = false;
                return
            }
            this.loadingCurrentPathData = true

            this.authedFetch("/access" + this.currentPath).then((data) => {
                this.currentPathData = data
                this.loadingCurrentPathData = false
            })
        },
        goUp() {
            const splits = this.currentPath.split("/")
            this.setCurrentPath(splits.slice(0, splits.length - 1).join("/"))
        },
        handleCreateMountClick() {
            this.showCreateMountDialog = false
            this.loadingMounting = true
            this.authedFetch("/do/mount", this.selectedRepoInfoToMount, "POST").then((_) => this.updateMounts()).then((_) => this.loadingMounting = false)
        },
        umount(path) {
            this.loadingMounting = true
            if (this.currentPath.includes(path)) this.setCurrentPath("~")
            this.authedFetch("/do/umount", { path }, "POST").then((_) => this.updateMounts()).then((_) => this.loadingMounting = false)
        },
        showFile(path, size) {
            this.selectedFileToShow = path.split("/")[path.split("/").length - 1]
            if (size > 128 * 1024) {
                this.selectedFileContent = "größer als 128 KB, wird nicht angezeigt"
                this.showFileContentDialog = true
                return
            }
            const filename = path.split("/")[path.split("/").length - 1]
            this.downloadingFiles.push(filename)
            this.authedFetch("/access/" + path).then((data) => {
                this.selectedFileContent = "..."
                if (data.seems_like_text) {
                    this.decompressBase64Gzip(data.base64_gzip_content).then((b) => this.selectedFileContent = new Option(b).innerHTML.replaceAll("\n", "<br>").replaceAll(" ", "&nbsp;"))
                } else {
                    this.selectedFileContent = "&lt;binary file&gt;"
                }
                this.showFileContentDialog = true
                this.downloadingFiles = this.downloadingFiles.filter((entry) => entry != filename)
            })
        },
        async downloadFile(url) {
            // Change this to use your HTTP client
            const filename = url.split("/")[url.split("/").length - 1].replaceAll("?download", "").replaceAll("?gzip", "")
            this.downloadingFiles.push(filename)
            fetch(url, { headers: { "Authorization": "Bearer " + this.account.token } }) // FETCH BLOB FROM IT
                .then((response) => response.blob())
                .then(async (blob) => { // RETRIEVE THE BLOB AND CREATE LOCAL URL
                    const decompressionStream = new DecompressionStream('gzip');
                    const decompressedStream = blob.stream().pipeThrough(decompressionStream);

                    var _url = window.URL.createObjectURL(await new Response(decompressedStream).blob());

                    const link = document.createElement('a');
                    link.href = _url;
                    link.download = filename; // Set desired filename

                    link.click();

                    URL.revokeObjectURL(_url);
                }).catch((err) => {
                    console.log(err);
                }).then((_) => this.downloadingFiles = this.downloadingFiles.filter((entry) => entry != filename));
        },
        async decompressBase64Gzip(base64Data) {
            // Decode base64
            const compressedData = atob(base64Data);

            // Convert binary string to Uint8Array
            const bytes = new Uint8Array(compressedData.length);
            for (let i = 0; i < compressedData.length; i++) {
                bytes[i] = compressedData.charCodeAt(i);
            }

            // Create a readable stream from the compressed data
            const readableStream = new ReadableStream({
                start(controller) {
                    controller.enqueue(bytes);
                    controller.close();
                }
            });

            // Create a DecompressionStream with 'gzip' algorithm
            const decompressionStream = new DecompressionStream('gzip');

            // Pipe the readable stream through the DecompressionStream
            const decompressedStream = readableStream.pipeThrough(decompressionStream);

            const decompressedData = await new Response(decompressedStream).text();

            return decompressedData;
        },
        async authedFetch(url, data, method = "GET") {
            const res = await fetch(url, { method, body: JSON.stringify(data), headers: { "Authorization": "Bearer " + this.account.token } })
            return await res.json()
        },
        formatBytes(bytes, decimals = 2) {
            if(bytes === 0) return '0 B';

            const k = 1024;
            const dm = decimals < 0 ? 0 : decimals;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];

            const i = Math.floor(Math.log(bytes) / Math.log(k));

            return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
        },
        base64ToBytes(base64) {
            const binString = atob(base64);
            return Uint8Array.from(binString, (m) => m.codePointAt(0));
        },

        async handleRegisterPasskey() {
            const { startRegistration } = SimpleWebAuthnBrowser;
            const resp = await this.authedFetch("/webauthn/registration/options");

            let attResp;
            try {
                // Pass the options to the authenticator and wait for a response
                attResp = await startRegistration(resp);
            } catch (error) {
                console.error(error);
                alert("Fehler beim Registrieren des Passkeys! Abbruch.");
                return;
            }

            const name = prompt("Bitte gebe einen Namen für deinen Passkey ein:") ?? "Unbenannter Passkey von " + navigator.userAgent.split(" ").at(-1);

            const verifData = await this.authedFetch("/webauthn/registration/handle", {...attResp, name}, "POST");

            if (verifData.verified) {
                alert("Erfolgreich hinzugefügt!");
                if (this.passkeys.length == 0) {
                    this.updateMounts()
                }
                this.updatePasskeys();
            } else {
                alert("Server-Fehler beim Registrieren des Passkeys!");
            }
        },
        async removePasskey(id) {
            if (!confirm("Passkey \"" + id + "\" wirklich entfernen?")) return;
            const resp = await this.authedFetch("/remove/passkey/" + id);
            if (resp.success) {
                alert("Erfolgreich entfernt!");
            } else {
                alert("Fehler beim Entfernen!");
            }
            this.updatePasskeys();
        },
        async show2FACode() {
            const resp = await this.authedFetch("/webauthn/2fa-code");
            if (resp.code) {
                this.show2FACodeDialog = true;
                this.known2FACodeData = resp.code;
            } else {
                alert("Fehler beim Abfragen.");
            }
        },
        async handlePasskeyLogin() {
            const { startAuthentication } = SimpleWebAuthnBrowser;
            const resp = await fetch("/auth/login/2fa/webauthn/options", { headers: { Authorization: "Bearer " + this.tempToken } });

            let attResp;
            try {
                // Pass the options to the authenticator and wait for a response
                attResp = await startAuthentication(await resp.json());
            } catch (error) {
                console.error(error);
                alert("Fehler beim Anmelden mit dem Passkeys! Abbruch.");
                return;
            }

            const verifData = await fetch("/auth/login/2fa/webauthn/handle", { method: "POST", body: JSON.stringify(attResp), headers: { Authorization: "Bearer " + this.tempToken, "Content-Type": "application/json" } });

            const json = await verifData.json();
            if (json.token) {
                this.showConfirm2FADialog = false;
                this.account = { login: this.loginModel.login, token: json.token };
                window.localStorage.setItem("account", JSON.stringify(this.account));
                this.updateMounts();
                this.updatePasskeys();
            } else {
                alert("Fehler beim Anmelden!");
            }
        },
        async handle2FACodeLogin() {
            const resp = await fetch("/auth/login/2fa/code", { headers: { Authorization: "Bearer " + this.tempToken }, method: "POST", body: JSON.stringify({ code: this.input2FACode }) });
            this.input2FACode = "";
            const json = await resp.json();
            if (json.token) {
                this.showConfirm2FADialog = false;
                this.account = { login: this.loginModel.login, token: json.token };
                window.localStorage.setItem("account", JSON.stringify(this.account));
                this.updateMounts();
                this.updatePasskeys();
            } else {
                alert("Fehler beim Anmelden!");
            }
        }
    }
}).use(vuetify).mount("#app")
