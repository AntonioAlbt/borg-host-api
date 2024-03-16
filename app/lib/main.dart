import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/widgets.dart';
import 'package:http/http.dart';
import 'package:provider/provider.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Borg Repo Viewer',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.teal),
        useMaterial3: true,
      ),
      home: const HomePage(),
    );
  }
}

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

SharedPreferences? _prefs;
SharedPreferences get prefs => _prefs!;

class _HomePageState extends State<HomePage> {
  bool _loading = true;

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const Center(
        child: CircularProgressIndicator(),
      );
    }
    return ChangeNotifierProvider<AppState>(
      create: (_) => AppState.loadFromPrefs(),
      builder: (context, _) => Scaffold(
        appBar: AppBar(title: const Text("Borg Repo Viewer"), elevation: 2),
        body: Consumer<AppState>(
          builder: (ctx, state, _) {
            if (state._login == "" || state.token == "") {
              return const LoginView();
            } else {
              return const MainView();
            }
          },
        ),
      ),
    );
  }

  @override
  void initState() {
    super.initState();
    () async {
      _prefs = await SharedPreferences.getInstance();
      setState(() => _loading = false);
    }();
  }
}

class AppState extends ChangeNotifier {
  AppState.loadFromPrefs() {
    if (prefs.containsKey("host")) _host = prefs.getString("host")!;
    if (prefs.containsKey("login")) _login = prefs.getString("login")!;
    if (prefs.containsKey("token")) _token = prefs.getString("token")!;
    if (prefs.containsKey("rpdata")) _rawRepoData = prefs.getStringList("rpdata")!;
  }

  String _host = "";
  Uri get host => Uri.parse(_host);
  set host(Uri val) {
    _host = val.toString();
    prefs.setString("host", val.toString());
    notifyListeners();
  }
  Uri hostWithPath(String path) => Uri.parse(_host + path);

  String _login = "";
  String get login => _login;
  set login(String val) {
    _login = val;
    prefs.setString("login", val);
    notifyListeners();
  }

  String _token = "";
  String get token => _token;
  set token(String val) {
    _token = val;
    prefs.setString("token", val);
    notifyListeners();
  }

  void clearLoginData() {
    _host = "";
    prefs.setString("host", "");
    _login = "";
    prefs.setString("login", "");
    _token = "";
    prefs.setString("token", "");
    notifyListeners();
  }

  static const rdSep = "-|^s°?|+";
  List<String> _rawRepoData = [];
  List<RepoData> get repoData => _rawRepoData.map((s) => RepoData(s.split(rdSep)[0], s.split(rdSep)[1])).toList();
  set repoData(List<RepoData> val) {
    _rawRepoData = val.map((v) => "${v.url}$rdSep${v.passphrase}").toList();
    prefs.setStringList("rpdata", _rawRepoData);
    notifyListeners();
  }
}

class RepoData {
  final String url;
  final String passphrase;

  RepoData(this.url, this.passphrase);
}


class LoginView extends StatefulWidget {
  const LoginView({super.key});

  @override
  State<LoginView> createState() => _LoginViewState();
}

class _LoginViewState extends State<LoginView> {
  final TextEditingController _hostController = TextEditingController();
  final TextEditingController _loginController = TextEditingController();
  final TextEditingController _pwController = TextEditingController();

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      child: Center(
        child: Card(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 400),
            child: Padding(
              padding: const EdgeInsets.all(8.0),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const Text("Please log in to your borg-host-api instance."),
                  TextField(controller: _hostController, decoration: const InputDecoration(labelText: "API Host")),
                  TextField(controller: _loginController, decoration: const InputDecoration(labelText: "Login")),
                  TextField(controller: _pwController, obscureText: true, decoration: const InputDecoration(labelText: "Password")),
                  Padding(
                    padding: const EdgeInsets.only(top: 8),
                    child: ElevatedButton(
                      onPressed: _handleLogin,
                      child: const Text("Log in"),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  Future<void> _handleLogin() async {
    if (Uri.tryParse(_hostController.text) == null || !_hostController.text.contains("://")) {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("Invalid host address.")));
      return;
    }
    if (_loginController.text == "") {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("Login is required.")));
      return;
    }
    if (_pwController.text == "") {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("Password is required.")));
      return;
    }

    final state = Provider.of<AppState>(context, listen: false);

    final hostStr = _hostController.text;
    state.host = Uri.parse(hostStr.endsWith("/") ? hostStr.substring(0, hostStr.length - 1) : hostStr);
    final password = _pwController.text;

    final data = jsonDecode(
      (await post(
        state.hostWithPath("/auth/login"),
        headers: { "content-type": "text/plain" },
        body: jsonEncode({ "login": _loginController.text, "pw": password, "appname": "BorgRepoViewer-Flutter-${kIsWeb ? "Web" : Platform.isAndroid ? "Android" : "Other"}" }),
      )).body,
    ) as Map<dynamic, dynamic>;
    if (!mounted) return;
    if (data.containsKey("error") || !data.containsKey("token")) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text("Error with logging in: ${data["error"]}")));
      return;
    }
    final token = data["token"];

    state.login = _loginController.text;
    state.token = token;
  }
}

class MainView extends StatefulWidget {
  const MainView({super.key});

  @override
  State<MainView> createState() => _MainViewState();
}

class _MainViewState extends State<MainView> {
  bool loadingLCheck = true;
  List<Mount> mounts = [];
  bool wsConnected = false;
  WebSocketChannel? webSocketChannel;
  String? selectedMountPath;
  bool loadingMounting = false;

  TextEditingController textField1Controller = TextEditingController();
  TextEditingController textField2Controller = TextEditingController();

  @override
  Widget build(BuildContext context) {
    if (loadingLCheck) {
      return const Padding(
        padding: EdgeInsets.all(8.0),
        child: Column(
          children: [
            Text("Checking login information..."),
            Padding(
              padding: EdgeInsets.all(8.0),
              child: CircularProgressIndicator(),
            ),
          ],
        ),
      );
    }
    return SingleChildScrollView(
      child: Padding(
        padding: const EdgeInsets.all(8.0),
        child: Consumer<AppState>(
          builder: (context, state, _) => Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Wrap(
                  crossAxisAlignment: WrapCrossAlignment.center,
                  spacing: 4,
                  runSpacing: 4,
                  children: [
                    Text("logged in as ${state.login} on ${state.host}"),
                    ElevatedButton(
                      onPressed: () {
                        setState(() {
                          loadingLCheck = true;
                        });
                        authedGet(state.hostWithPath("/auth/remove-token")).then((_) => state.clearLoginData());
                      },
                      child: const Text("Log out"),
                    ),
                  ],
                ),
              ),
              Text("${wsConnected ? "" : "Warning: not "}connected to WebSocket"),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(8.0),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text("Available Repos", style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600)),
                      if (state.repoData.isEmpty) const Text("No repos available."),
                      ...state.repoData.map((r) => Text(r.url)),
                      ElevatedButton(
                        onPressed: () {
                          showDialog(
                            context: context,
                            builder: (ctx) => AlertDialog(
                              title: const Text("Add repo"),
                              content: SingleChildScrollView(
                                child: Column(
                                  mainAxisSize: MainAxisSize.min,
                                  children: [
                                    const Text("This is only checked when mounting."),
                                    TextField(
                                      controller: textField1Controller,
                                      decoration: const InputDecoration(
                                        label: Text("Repo URL"),
                                      ),
                                    ),
                                    TextField(
                                      controller: textField2Controller,
                                      decoration: const InputDecoration(
                                        label: Text("Passphrase"),
                                      ),
                                      obscureText: true,
                                    ),
                                    ElevatedButton(
                                      onPressed: () {
                                        state.repoData = state.repoData
                                          ..add(RepoData(textField1Controller.text, textField2Controller.text));
                                        Navigator.pop(ctx);
                                        textField1Controller.text = "";
                                        textField2Controller.text = "";
                                      },
                                      child: const Text("Add"),
                                    ),
                                  ],
                                ),
                              ),
                            ),
                          );
                        },
                        child: const Text("Add repo"),
                      ),
                    ],
                  ),
                ),
              ),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(8.0),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text("Available Mounts", style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600)),
                      if (mounts.isEmpty) const Text("No mounts available."),
                      ...mounts.map(
                        (mount) => MountDisplay(
                          mount: mount,
                          onSelect: () {
                            if (!mounted) return;
                            setState(() {
                              selectedMountPath = mount.path;
                            });
                          },
                          onUmount: () {
                            authedPost(state.hostWithPath("/do/umount"), { "path": mount.path }).then((_) => setState(() {
                              if (selectedMountPath?.startsWith(mount.path) == true) selectedMountPath = null;
                            }));
                          },
                        ),
                      ),
                      ElevatedButton(
                        onPressed: wsConnected ? () {
                          showDialog(
                            context: context,
                            builder: (ctx) => AlertDialog(
                              title: const Text("Do mount"),
                              content: SingleChildScrollView(
                                child: Column(
                                  mainAxisSize: MainAxisSize.min,
                                  children: [
                                    Flexible(
                                      child: DropdownMenu<RepoData>(
                                        dropdownMenuEntries: state.repoData.map((repo) => DropdownMenuEntry(value: repo, label: repo.url)).toList(),
                                        enableFilter: false,
                                        onSelected: (repoData) {
                                          setState(() {
                                            loadingMounting = true;
                                          });
                                          authedPost(state.hostWithPath("/do/mount"), { "repo": repoData!.url, "passphrase": repoData.passphrase })
                                            .then((_) => setState(() { loadingMounting = false; }));
                                          Navigator.pop(ctx);
                                        },
                                      ),
                                    ),
                                  ],
                                ),
                              ),
                            ),
                          );
                        } : null,
                        child: const Text("Mount"),
                      ),
                      if (loadingMounting) Padding(
                        padding: const EdgeInsets.all(8.0),
                        child: Row(
                          children: [
                            Transform.scale(scale: .7, child: const CircularProgressIndicator()),
                            const Padding(
                              padding: EdgeInsets.only(left: 6),
                              child: Text("Mounting..."),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  @override
  void initState() {
    super.initState();
    checkLogin().then((res) {
      if (!res) return;
      loadMounts();
      connectWS();
    });
  }

  Future<bool> checkLogin() async {
    setState(() {
      loadingLCheck = true;
    });
    final state = Provider.of<AppState>(context, listen: false);

    final res = await authedGet(state.hostWithPath("/auth/check"));
    final data = jsonDecode(res.body);
    if (data.containsKey("error")) {
      setState(() {
        loadingLCheck = false;
      });
      return false;
    }
    state.login = data["owner"]["login"];
    setState(() {
      loadingLCheck = false;
    });
    return true;
  }

  Future<void> loadMounts() async {
    final state = Provider.of<AppState>(context, listen: false);
    
    final res = await authedGet(state.hostWithPath("/get/mounts"));
    final data = jsonDecode(res.body);
    if (data.containsKey("error")) return;
    final list = data["mounts"].toList() as List<dynamic>;
    // print("${list.runtimeType} -> $list");
    mounts = list.map((v) => Mount(v["path"], v["repo"], v["access_ms"], v["umount_in_ms"])).toList();
    setState(() {});
  }

  Future<void> connectWS() async {
    if (!mounted) return;
    setState(() {
      wsConnected = false;
    });
    final state = Provider.of<AppState>(context, listen: false);
    // my god this replacement is smart, because if it was https it will now be wss (secure websocket)
    final WebSocketChannel channel;
    try {
      channel = WebSocketChannel.connect(Uri.parse(state.hostWithPath("/watch/mounts/${state.token}").toString().replaceFirst("http", "ws")));
      await channel.ready;
    } catch (_) {
      await Future.delayed(const Duration(seconds: 5));
      return connectWS();
    }
    webSocketChannel = channel;
    setState(() {
      wsConnected = true;
    });
    await for (final msg in channel.stream) {
      final data = jsonDecode(msg) as Map<dynamic, dynamic>;
      if (data.containsKey("event")) {
        if (data["event"] == "mount") {
          mounts.add(Mount(data["path"], data["repo"], data["access_ms"], data["umount_in_ms"]));
          setState(() {});
        } else if (data["event"] == "umount") {
          setState(() {
            mounts = mounts.where((m) => m.path != data["path"]).toList();
          });
        }
      }
    }
    channel.sink.close();
    webSocketChannel = null;
    if (!mounted) return;
    setState(() {
      wsConnected = false;
    });
    await Future.delayed(const Duration(seconds: 5));
    loadMounts();
    return connectWS();
  }

  Future<Response> authedGet(Uri url) {
    final state = Provider.of<AppState>(context, listen: false);
    return get(url, headers: { "Authorization": "Bearer ${state.token}" });
  }
  Future<Response> authedPost(Uri url, dynamic body) {
    final state = Provider.of<AppState>(context, listen: false);
    return post(url, headers: { "Authorization": "Bearer ${state.token}" }, body: jsonEncode(body));
  }

  @override
  void dispose() {
    super.dispose();
    webSocketChannel?.sink.close();
  }
}


class Mount {
  final String path;
  final String repo;
  final int lastAccessMs;
  int umountInMs;

  Mount(this.path, this.repo, this.lastAccessMs, this.umountInMs);

  void updateUmountTime(int ms) {
    umountInMs = ms;
  }
}

class MountDisplay extends StatefulWidget {
  final Mount mount;
  final VoidCallback onSelect;
  final VoidCallback onUmount;
  const MountDisplay({super.key, required this.mount, required this.onSelect, required this.onUmount});

  @override
  State<MountDisplay> createState() => _MountDisplayState();
}

class _MountDisplayState extends State<MountDisplay> {
  late int remainingSeconds;

  @override
  Widget build(BuildContext context) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        Wrap(
          children: [
            const Icon(Icons.save),
            Text(widget.mount.repo),
            Text("  (${widget.mount.path})", style: const TextStyle(fontSize: 10)),
            Text(", for $remainingSeconds s", style: const TextStyle(fontSize: 14)),
          ],
        ),
        Wrap(
          spacing: 8,
          children: [
            ElevatedButton(onPressed: widget.onSelect, child: const Text("View")),
            ElevatedButton(onPressed: widget.onUmount, child: const Text("Umount")),
          ],
        ),
      ],
    );
  }

  @override
  void initState() {
    remainingSeconds = (widget.mount.umountInMs / 1000).round();
    Timer.periodic(
      const Duration(seconds: 1),
      (timer) {
        if (!mounted) {
          timer.cancel();
          return;
        }
        if (remainingSeconds < 1) {
          timer.cancel();
        } else {
          setState(() {
            remainingSeconds--;
          });
        }
      }
    );
    super.initState();
  }
}
