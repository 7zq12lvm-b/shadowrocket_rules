/**
 * Clash / Mihomo 全局扩展脚本。
 * 公开版：仅在客户端的本地副本填写凭据，不要将凭据提交到 GitHub。
 *
 * 重命名范围：运行脚本时 config.proxies 中的订阅节点。
 * proxy-providers 后续下载的节点不在此范围内。
 * 编号按订阅顺序分配；订阅顺序改变时编号可能改变。
 * 自定义节点、无法识别地区的节点保留原名。
 * 按名称筛选的 filter / exclude-filter 请改用新名称，例如 ^HK[0-9]+$。
 */

const SCRIPT_SETTINGS = {
  sshDomain: "colocrossing.3455432.xyz",
  renameSubscriptionNodes: true,
  tailscaleRoutes: ["100.64.0.0/10", "fd7a:115c:a1e0::/48"],
  customNodes: [
    {
      name: "UMich", type: "ss", server: "8.163.100.82", port: 6822,
      cipher: "aes-128-gcm", password: "__LOCAL_UMICH_PASSWORD__",
      tfo: true, udp: true,
    },
    {
      name: "Colo-Shadowsocks", type: "ss", server: "192.3.242.113", port: 32816,
      cipher: "chacha20-ietf-poly1305", password: "__LOCAL_COLO_SS_PASSWORD__",
      udp: true,
    },
    {
      name: "Colo-VMess", type: "vmess", server: "192.3.242.113", port: 44615,
      uuid: "__LOCAL_COLO_VMESS_UUID__", alterId: 0, cipher: "auto",
      network: "tcp", tls: false, udp: true,
    },
  ],
};

// ISO 两字母代码；英国统一输出 UK，台湾/香港/澳门分别输出 TW/HK/MO。
const COUNTRY_ALIASES = [
  ["HK", "香港|Hong[ -]?Kong"], ["TW", "台湾|台灣|Taiwan"],
  ["MO", "澳门|澳門|Macau|Macao"], ["CN", "中国|中國|大陆|大陸|China"],
  ["JP", "日本|Japan"], ["SG", "新加坡|狮城|獅城|Singapore"],
  ["US", "美国|美國|United States|USA|America"],
  ["UK", "英国|英國|United Kingdom|Great Britain|Britain"],
  ["KR", "韩国|韓國|南韩|南韓|South Korea|Korea"],
  ["CA", "加拿大|Canada"], ["AU", "澳大利亚|澳大利亞|澳洲|Australia"],
  ["DE", "德国|德國|Germany"], ["FR", "法国|法國|France"],
  ["NL", "荷兰|荷蘭|Netherlands|Holland"], ["RU", "俄罗斯|俄羅斯|Russia"],
  ["IN", "印度|India"], ["ID", "印度尼西亚|印度尼西亞|印尼|Indonesia"],
  ["MY", "马来西亚|馬來西亞|Malaysia"], ["TH", "泰国|泰國|Thailand"],
  ["VN", "越南|Vietnam"], ["PH", "菲律宾|菲律賓|Philippines"],
  ["KH", "柬埔寨|Cambodia"], ["NZ", "新西兰|新西蘭|紐西蘭|New Zealand"],
  ["TR", "土耳其|Turkey|Türkiye"], ["AE", "阿联酋|阿聯酋|迪拜|杜拜|United Arab Emirates|UAE|Dubai"],
  ["BR", "巴西|Brazil"], ["AR", "阿根廷|Argentina"], ["CL", "智利|Chile"],
  ["MX", "墨西哥|Mexico"], ["ZA", "南非|South Africa"],
  ["EG", "埃及|Egypt"], ["SA", "沙特|沙烏地|Saudi Arabia"],
  ["IL", "以色列|Israel"], ["BH", "巴林|Bahrain"], ["KZ", "哈萨克斯坦|哈薩克斯坦|Kazakhstan"],
  ["IT", "意大利|義大利|Italy"], ["ES", "西班牙|Spain"],
  ["PT", "葡萄牙|Portugal"], ["CH", "瑞士|Switzerland"],
  ["SE", "瑞典|Sweden"], ["NO", "挪威|Norway"], ["FI", "芬兰|芬蘭|Finland"],
  ["DK", "丹麦|丹麥|Denmark"], ["IE", "爱尔兰|愛爾蘭|Ireland"],
  ["AT", "奥地利|奧地利|Austria"], ["BE", "比利时|比利時|Belgium"],
  ["PL", "波兰|波蘭|Poland"], ["CZ", "捷克|Czechia|Czech Republic"],
  ["UA", "乌克兰|烏克蘭|Ukraine"], ["HU", "匈牙利|Hungary"],
  ["RO", "罗马尼亚|羅馬尼亞|Romania"], ["IS", "冰岛|冰島|Iceland"],
  ["GR", "希腊|希臘|Greece"], ["LU", "卢森堡|盧森堡|Luxembourg"],
];

function main(config) {
  configureRealIpDns(config);
  configureTunExclusions(config);
  configureDirectRules(config);
  if (SCRIPT_SETTINGS.renameSubscriptionNodes) renameSubscriptionProxies(config);
  const customNames = upsertCustomProxies(config);
  appendCustomProxiesToSelectGroups(config, customNames);
  return config;
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function unique(values) {
  return Array.from(new Set(values));
}

function configureRealIpDns(config) {
  const dns = config.dns || (config.dns = {});
  const domains = [SCRIPT_SETTINGS.sshDomain, "+.tailscale.com", "+.tailscale.io", "+.ts.net"];
  const realIpRules = [
    "DOMAIN," + SCRIPT_SETTINGS.sshDomain + ",real-ip",
    "DOMAIN-SUFFIX,tailscale.com,real-ip",
    "DOMAIN-SUFFIX,tailscale.io,real-ip",
    "DOMAIN-SUFFIX,ts.net,real-ip",
  ];
  const managed = new Set(domains.concat(realIpRules));
  const preserved = asArray(dns["fake-ip-filter"]).filter(entry => !managed.has(entry));
  if (dns["fake-ip-filter-mode"] === "whitelist") {
    // whitelist 的匹配项返回 fake-ip，不能直接把直连域名加进去。
    // 转为等价 rule 模式，优先 real-ip，再保留原白名单的 fake-ip 语义。
    const converted = preserved.map(convertWhitelistEntryToRule);
    dns["fake-ip-filter-mode"] = "rule";
    dns["fake-ip-filter"] = unique(realIpRules.concat(converted, ["MATCH,real-ip"]));
  } else {
    const entries = dns["fake-ip-filter-mode"] === "rule" ? realIpRules : domains;
    dns["fake-ip-filter"] = unique(entries.concat(preserved));
  }
}

function convertWhitelistEntryToRule(entry) {
  if (typeof entry !== "string") throw new Error("fake-ip-filter 必须为字符串数组");
  if (entry.startsWith("geosite:")) return "GEOSITE," + entry.slice(8) + ",fake-ip";
  if (entry.startsWith("rule-set:")) return "RULE-SET," + entry.slice(9) + ",fake-ip";
  if (entry === "*") return "MATCH,fake-ip";
  if (entry.startsWith("+.")) return "DOMAIN-SUFFIX," + entry.slice(2) + ",fake-ip";
  if (/[,\s:]/.test(entry)) {
    throw new Error("无法自动转换 DNS 白名单条目，请先改用 rule 模式：" + entry);
  }
  return (/[?*]/.test(entry) ? "DOMAIN-WILDCARD," : "DOMAIN,") + entry + ",fake-ip";
}

function configureTunExclusions(config) {
  const tun = config.tun || (config.tun = {});
  tun["route-exclude-address"] = unique(
    asArray(tun["route-exclude-address"]).concat(SCRIPT_SETTINGS.tailscaleRoutes)
  );
}

function configureDirectRules(config) {
  const rules = [
    "DOMAIN," + SCRIPT_SETTINGS.sshDomain + ",DIRECT",
    "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
    "IP-CIDR6,fd7a:115c:a1e0::/48,DIRECT,no-resolve",
  ];
  const managed = new Set(rules.concat([
    "DST-PORT,22,DIRECT", "IP-CIDR,198.18.0.0/16,DIRECT,no-resolve",
  ]));
  config.rules = rules.concat(asArray(config.rules).filter(rule => !managed.has(rule)));
}

function detectCountryCode(name) {
  // 国旗优先；区域指示符组成的两字母代码支持常见国家/地区国旗。
  const flag = name.match(/[\u{1F1E6}-\u{1F1FF}]{2}/u);
  if (flag) {
    const code = Array.from(flag[0]).map(char =>
      String.fromCharCode(char.codePointAt(0) - 0x1F1E6 + 65)
    ).join("");
    if (code !== "EU" && code !== "UN") return code === "GB" ? "UK" : code;
  }
  // 全称按最长匹配优先，例如“印度尼西亚”不能误判为“印度”。
  let best = null;
  for (const [code, aliases] of COUNTRY_ALIASES) {
    for (const alias of aliases.split("|")) {
      const latin = /^[A-Za-z]/.test(alias);
      const pattern = latin ? "(?:^|[^A-Za-z])(?:" + alias + ")(?=$|[^A-Za-z])" : alias;
      const match = name.match(new RegExp(pattern, "i"));
      if (match && (!best || match[0].length > best.length)) best = { code, length: match[0].length };
    }
  }
  if (best) return best.code;
  // 缩写使用大写且不嵌入英文单词，避免把 "in" / "no" 等误判为国家。
  const codes = COUNTRY_ALIASES.map(item => item[0]).concat(["GB"]);
  const match = name.match(new RegExp("(?:^|[^A-Za-z])(" + codes.join("|") + ")(?=$|[^A-Za-z])"));
  return match ? (match[1] === "GB" ? "UK" : match[1]) : null;
}

function renameSubscriptionProxies(config) {
  const proxies = asArray(config.proxies);
  const groups = asArray(config["proxy-groups"]);
  const customNames = new Set(SCRIPT_SETTINGS.customNodes.map(node => node.name));
  const groupNames = new Set(groups.map(group => group.name));
  const originalNames = new Set();
  for (const node of proxies) {
    if (originalNames.has(node.name) || groupNames.has(node.name)) {
      throw new Error("节点名称重复或与策略组重名，无法安全重命名：" + node.name);
    }
    originalNames.add(node.name);
  }
  const plans = proxies.map(node => ({
    node,
    code: customNames.has(node.name) ? null : detectCountryCode(node.name),
  }));
  const reserved = new Set(["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"]);
  groupNames.forEach(name => reserved.add(name));
  customNames.forEach(name => reserved.add(name));
  plans.filter(plan => !plan.code).forEach(plan => reserved.add(plan.node.name));
  const counters = Object.create(null);
  const renamed = new Map();
  for (const { node, code } of plans) {
    if (!code) continue;
    let newName;
    do {
      counters[code] = (counters[code] || 0) + 1;
      newName = code + counters[code];
    } while (reserved.has(newName));
    reserved.add(newName);
    renamed.set(node.name, newName);
    node.name = newName;
  }
  updateProxyReferences(config, renamed);
}

function updateProxyReferences(config, renamed) {
  const rename = name => renamed.has(name) ? renamed.get(name) : name;
  for (const group of asArray(config["proxy-groups"])) {
    if (Array.isArray(group.proxies)) group.proxies = group.proxies.map(rename);
    if (group["default-selected"]) group["default-selected"] = rename(group["default-selected"]);
  }
  for (const node of asArray(config.proxies)) {
    if (node["dialer-proxy"]) node["dialer-proxy"] = rename(node["dialer-proxy"]);
  }
  for (const key of ["proxy-providers", "rule-providers"]) {
    for (const provider of Object.values(config[key] || {})) {
      if (provider.proxy) provider.proxy = rename(provider.proxy);
      if (provider.override && provider.override["dialer-proxy"]) {
        provider.override["dialer-proxy"] = rename(provider.override["dialer-proxy"]);
      }
    }
  }
  const updateRule = rule => {
    if (typeof rule !== "string" || rule.startsWith("SUB-RULE,")) return rule;
    const parts = rule.split(",");
    let target = parts.length - 1;
    while (target > 0 && ["no-resolve", "src"].includes(parts[target].trim())) target--;
    if (target > 0) parts[target] = rename(parts[target].trim());
    return parts.join(",");
  };
  config.rules = asArray(config.rules).map(updateRule);
  for (const key of Object.keys(config["sub-rules"] || {})) {
    config["sub-rules"][key] = asArray(config["sub-rules"][key]).map(updateRule);
  }
}

function hasLocalCredentials(node) {
  const credential = node.type === "vmess" ? node.uuid : node.password;
  return typeof credential === "string" && credential.trim() !== "" && !credential.startsWith("__LOCAL_");
}

function upsertCustomProxies(config) {
  const nodes = SCRIPT_SETTINGS.customNodes.filter(hasLocalCredentials);
  const names = new Set(nodes.map(node => node.name));
  const groups = asArray(config["proxy-groups"]);
  if (groups.some(group => names.has(group.name))) throw new Error("自定义节点与策略组重名");
  // 缺少本地凭据时不注入、不删除订阅中已有的同名有效节点。
  config.proxies = asArray(config.proxies).filter(node => !names.has(node.name))
    .concat(nodes.map(node => Object.assign({}, node)));
  const configured = new Set(SCRIPT_SETTINGS.customNodes.map(node => node.name));
  return config.proxies.filter(node => configured.has(node.name) && hasLocalCredentials(node))
    .map(node => node.name);
}

function appendCustomProxiesToSelectGroups(config, names) {
  if (!names.length) return;
  for (const group of asArray(config["proxy-groups"])) {
    if (group.type === "select") group.proxies = unique(asArray(group.proxies).concat(names));
  }
}
