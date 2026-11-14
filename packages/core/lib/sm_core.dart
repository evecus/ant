library;

// models
export 'src/models/group.dart' show Group, defaultGroupID, defaultGroupName;
export 'src/models/node.dart';
// parsing
export 'src/parsing/clash_yaml.dart' show parseClashYaml;
export 'src/parsing/common.dart'
    show ParseException, newUuid, normalizeNetwork, parseAlpn, tryBase64Decode;
export 'src/parsing/content.dart' show parseContent, parseUriLines, splitLines;
export 'src/parsing/singbox_json.dart' show parseSingBoxJson;
export 'src/parsing/uri_parser.dart' show parseUri;
// config — ant 单内核
export 'src/config/builtin.dart'
    show
        isBuiltinMode,
        builtinDisplayName,
        parseBuiltinName,
        builtinDisplayNames,
        checkRuleFiles,
        builtinRuleFilesAll,
        antRuleFiles,
        antRulePath,
        antRuleDirName,
        antRuleExt,
        dnsModeRedirHost,
        dnsModeFakeIP,
        BuiltinOptions,
        buildBuiltinConfig;
export 'src/config/editor.dart'
    show
        applyNodeToConfig,
        setTun,
        setMixedInbound,
        hasTunInbound,
        findAppliedNodeId,
        removeNodeFromConfig,
        loadConfig,
        saveConfig,
        buildAntTunInbound;
export 'src/config/ant_edit.dart'
    show
        applyNodeToAntConfig,
        setTunAnt,
        hasTunAnt,
        setMixedInboundAnt,
        findAppliedNodeIDAnt,
        removeNodeFromAntConfig,
        cloneMap,
        loadYamlFile,
        saveYamlFile;
export 'src/config/settings.dart'
    show
        coreAnt,
        antConfigExts,
        modeCustom,
        modeBypass,
        modeBlacklist,
        modeGlobal,
        DNSServer,
        ClashAPIConfig,
        BuiltinSettings,
        Settings,
        defaultBuiltin;
export 'src/config/settings_manager.dart' show SettingsManager;
// storage
export 'src/storage/store.dart' show NodeStore;
// export
export 'src/export/ant_write.dart'
    show antProxyName, nodeToAntProxy, clashProxyToAntProxy;
export 'src/export/clash_write.dart' show nodeToClashProxy;
export 'src/export/node_export.dart' show nodeToUri;
// services
export 'src/services/app.dart'
    show SmApp, AppException, fetchSubscription;
export 'src/services/probe.dart' show probeTcp;
export 'src/services/real_probe.dart' show testLatencyReal, testSpeedReal;
