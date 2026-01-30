GameMode = nil

ProxiesData = {}
ProxyList = {
    "255.255.255.255",
    "244.244.244.244" -- Replace with your proxy IPs
}

disabledProxies = {

}

ProxyPairs = {}
AleardyWhitlelist = {}

local ApiKey = "SECRET_KEY_HERE"
local FivemIP = "REPLACE_WITH_FIVEM_SERVER_IP"
local FivemPort = 30120 -- Replace with your FiveM server port
local DomainName = "replaceby.domainname.fr"
local Name = "replacebyservername"
local LoadBalancer = "REPLACE_WITH_LOAD_BALANCER_IP"
local CacheProxy = "REPLACE_WITH_CACHE_PROXY_IP"
local ProxMox = "REPLACE_WITH_PROXMOX_IP (PROXY CONTAINER HOST)"

local ProxiesLoaded = false

local RateLimitDigit = {}

local doRandomProxies = false

function GeneratePort(pass, proxy)
    local generated = math.random(10000, 60000)
    if (generated == pass) or (proxy and ProxiesData[proxy] and ProxiesData[proxy].ports[tostring(generated)]) then
        return GeneratePort(pass)
    else
        return generated
    end 
end

function RegeneratePorts()
    ProxiesData = {}
    ProxyPairsProxyPairs = {}
    local endpointstring = ""
    local iprangesstring = ""
    local upstreamstring  = ""
    local proxiesCount = 0
    PerformHttpRequest(ProxMox .. ":40321/?key=" .. ApiKey .. "&action=setup&connectport=" .. 30000 .. "&proxyip=" .. ProxMox .. "&proxyport=" .. 30120 .. "&fivemip=" .. FivemIP .. "&fivemport=" .. FivemPort .. "&domainname=" .. DomainName .. "&loadbalancing=" .. LoadBalancer,function (errorCode, resultData, resultHeaders)
        print(ProxMox .. " " .. tostring(errorCode))
    end)
    for k, v in pairs(ProxyList) do
        ProxyPairs[v] = true
        local port = 30120
        local connectport = GeneratePort(port)
        local success = false
        endpointstring = endpointstring .. v .. ":" .. port .. " "
        if iprangesstring ~= "" then
            iprangesstring = iprangesstring .. " "
        end
        iprangesstring = iprangesstring .. v .."/32"
        if upstreamstring ~= "" then
            upstreamstring = upstreamstring .. "[space][space][space][space]"
        end
        upstreamstring = upstreamstring .. "server[space]" .. v .. ":" .. connectport .. ";[backtoline]"
        print(v)
        local pLoaded = false
        PerformHttpRequest(v .. ":40321/?key=" .. ApiKey .. "&action=setup&connectport=" .. connectport .. "&proxyip=" .. v .. "&proxyport=" .. port .. "&fivemip=" .. FivemIP .. "&fivemport=" .. FivemPort .. "&domainname=" .. DomainName .. "&loadbalancing=" .. LoadBalancer,function (errorCode, resultData, resultHeaders)
            if tostring(errorCode) == "200" then
                ProxiesData[v] = {ip = v, port = port, players = {}, key = k, ports = {
                    [tostring(port)] = true,
                    [tostring(connectport)] = true,
                }}
                pLoaded = true
                proxiesCount = proxiesCount + 1
            else
                ProxiesData[v] = nil
                pLoaded = true
            end
            print(v .. " " .. tostring(errorCode))
        end)
    end
    --TriggerEvent("DigitProtect:ProxyPairs", ProxyPairs)
    PerformHttpRequest(LoadBalancer .. ":40321/?key=" .. ApiKey .. "&action=setup&name=" .. Name .. "&serverslist=" .. upstreamstring,function (errorCode, resultData, resultHeaders)
    end)

    return ProxiesData
end

RegeneratePorts()

function mysplit(inputstr, sep)
    if sep == nil then
       sep = "%s"
    end
    local t={}
    for str in string.gmatch(inputstr, "([^"..sep.."]+)") do
       table.insert(t, str)
    end
    return t
 end

AddEventHandler("DigitProtect:WhiteListPlayer", function(source, _identifier, _callback) -- Trigger this event at playerConnecting in order to whitelist the player before connecting (pay attention to defer the connection and end defering after whitelist)
    local _source = source
    local callback = _callback
    local identifier = _identifier
    local playerip = _GetPlayerEndpoint(_source)
    local randomProxy = math.random(#ProxyList)
    local proxy = ProxyList[randomProxy]


    if proxy == "" or playerip == "" then 
        if playerip == "" then
            callback("Une erreur est survenue pendant la connexion") 
            return 
        end
    end
    if not proxy or not playerip or proxy == "" or playerip == "" then
        callback("Une erreur est survenue pendant la connexion")
        return
    end
    
    local proxyport = GeneratePort(30120, proxy)
    proxyport = 30120
    print((GetPlayerName(_source) or "Unknown") .. " with ip " .. playerip .. " is connecting on proxy " .. proxy .. " with port " .. proxyport)
    callback(false)
    if AleardyWhitlelist[identifier] then
        unwhitelistPlayer(identifier, 2)
    end
    local timeout = 0
    while AleardyWhitlelist[identifier] and timeout < 20 do
        timeout = timeout + 1
        Wait(500)
    end
    PerformHttpRequest(ProxMox .. ":40321/?key=" .. ApiKey .. "&action=set&ip=" .. playerip .. "&port=" .. proxyport .. "&proxyip=" .. proxy,function (errorCode, resultData, resultHeaders)
        if tostring(errorCode) == "200" then
            if tostring(resultData) == "true" then
                PerformHttpRequest(proxy .. ":40321/?key=" .. ApiKey .. "&action=set&ip=" .. playerip .. "&port=" .. proxyport .. "&proxyip=" .. proxy,function (errorCode, resultData, resultHeaders)
                    if tostring(errorCode) == "200" then
                        if tostring(resultData) == "true" then
                            AleardyWhitlelist[identifier] = {source = _source, proxy = proxy, ip = playerip, port = proxyport}
                            if not ProxiesData[proxy].players then
                                ProxiesData[proxy].players = {}
                            end
                            table.insert(ProxiesData[proxy].players, {source = _source, ip = playerip, port = proxyport, identifier = identifier, timestamp = os.time()})
                            ExecuteCommand("set sv_endpoints \"" .. proxy .. ":" .. proxyport .. "\"")
                            callback(false)
                            ProxiesData[proxy].ports[tostring(proxyport)] = true
                        end
                    end
                end)
            end
        end
        print(resultData, errorCode)
    end)
    PerformHttpRequest(CacheProxy .. ":40321/?key=" .. ApiKey .. "&action=set&ip=" .. playerip,function (errorCode, resultData, resultHeaders)
    end)
end)

AddEventHandler('gamemode:playerLoaded', function(playerId, xPlayer)
    if AleardyWhitlelist[xPlayer.identifier] then
        AleardyWhitlelist[xPlayer.identifier].source = xPlayer.source
    end
end)

AddEventHandler("playerDropped", function(reason)
    local _source = source
    local identifier = ""
	for k,v in ipairs(GetPlayerIdentifiers(_source)) do
		if string.match(v, 'license:') then
			identifier = string.sub(v, 9)
			break
		end
	end
    unwhitelistPlayer(identifier, 1)
end)

function unwhitelistPlayer(identifier, attempt)
    if AleardyWhitlelist[identifier] then
        local attempt = attempt + 1
        local proxy = AleardyWhitlelist[identifier].proxy
        local proxyport = AleardyWhitlelist[identifier].port
        PerformHttpRequest(ProxMox .. ":40321/?key=" .. ApiKey .. "&action=drop&ip=" .. AleardyWhitlelist[identifier].ip .. "&port=" .. proxyport .. "&proxyip=" .. proxy,function (errorCode, resultData, resultHeaders)
            if tostring(errorCode) == "200" then
                for k, v in pairs(ProxiesData[proxy].players) do
                    if v.identifier == identifier then
                        table.remove(ProxiesData[proxy].players, k)
                        break
                    end
                end
                AleardyWhitlelist[identifier] = nil
            end
        end)
        PerformHttpRequest(CacheProxy .. ":40321/?key=" .. ApiKey .. "&action=drop&ip=" .. AleardyWhitlelist[identifier].ip,function (errorCode, resultData, resultHeaders)
        end)
    else
        return false
    end
end

RegisterCommand("resetproxiesplayerlist", function(source, args, rawCommand)
    if source ~= 0 then return end
    for k, v in pairs(ProxiesData) do
        ProxiesData[k].players = {}
    end
end, false)

RegisterCommand("randomproxies", function(source, args, rawCommand)
    if source ~= 0 then return end
    doRandomProxies = not doRandomProxies
    print("Random proxies is now " .. tostring(doRandomProxies))
end, false)

RegisterCommand("proxies", function(source, args, rawCommand)
    if source ~= 0 then return end
    print(json.encode(ProxiesData))
end, false)

RegisterCommand("toggleProxy", function(source, args, rawCommand)
    if source ~= 0 then return end
    local proxy = args[1]
    if not proxy then return end
    disabledProxies[proxy] = not disabledProxies[proxy]
    print("Proxy " .. proxy .. " is now " .. tostring(disabledProxies[proxy]))
end, false)