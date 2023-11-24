// create a context menu

/*
 * AI
 */

chrome.contextMenus.create({
    "id": "AI",
    "title": "AI",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "--All AI--",
    "title": "Open in all",
    "contexts": ["selection", "link", "image", "video", "audio"],
    "parentId": "AI"
});

chrome.contextMenus.create({
    "id": "Phind",
    "title": "Phind",
    "parentId": "AI",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "You AI",
    "title": "You AI",
    "parentId": "AI",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "Metaphor",
    "title": "Metaphor",
    "parentId": "AI",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "Komo AI",
    "title": "Komo AI",
    "parentId": "AI",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "AndiSearch",
    "title": "AndiSearch",
    "parentId": "AI",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "Perplexity",
    "title": "Perplexity",
    "parentId": "AI",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "Yep AI",
    "title": "Yep AI",
    "parentId": "AI",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

/*
 * IPs
 */
chrome.contextMenus.create({
    "id": "IP",
    "title": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "--All IP--",
    "title": "Open in all",
    "contexts": ["selection", "link", "image", "video", "audio"],
    "parentId": "IP"
});

chrome.contextMenus.create({
    "id": "AbuseIPDB",
    "title": "AbuseIPDB",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "Alien IP",
    "title": "AlienVault OTX",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "ARIN IP",
    "title": "ARIN",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "FortiGuard IP",
    "title": "FortiGuard",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "GreyNoise IP",
    "title": "GreyNoise",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "IPinfo IP",
    "title": "IPinfo",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "IP Quality Score",
    "title": "IP Quality Score",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "MX Toolbox ARIN IP",
    "title": "MX Toolbox",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "Pulsedive IP",
    "title": "Pulsedive",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "Scamalytics IP",
    "title": "Scamalytics",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "Spyse IP",
    "title": "Spyse",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "Talos IP",
    "title": "Talos",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "URLhaus IP",
    "title": "URLhaus",
    "parentId": "IP",
    "contexts": ["selection", "link", "image", "video", "audio"]
});
/*
 * Domains
 */
chrome.contextMenus.create({
    "id": "Domain",
    "title": "Domain",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "--All Domain--",
    "title": "Open in all",
    "contexts": ["selection", "link", "image", "video", "audio"],
    "parentId": "Domain"
});

chrome.contextMenus.create({
    "id": "BlueCoat Domain",
    "title": "BlueCoat",
    "parentId": "Domain",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "FortiGuard Domain",
    "title": "FortiGuard",
    "parentId": "Domain",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "MX Toolbox Domain",
    "title": "MX Toolbox",
    "parentId": "Domain",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "Pulsedive Domain",
    "title": "Pulsedive",
    "parentId": "Domain",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "URLhaus Domain",
    "title": "URLhaus",
    "parentId": "Domain",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

/*
 * Hashes
 */
chrome.contextMenus.create({
    "id": "Hash",
    "title": "Hash",
    "contexts": ["selection"]
});

chrome.contextMenus.create({
    "id": "--All Hash--",
    "title": "Open in all",
    "contexts": ["selection"],
    "parentId": "Hash",
});

chrome.contextMenus.create({
    "id": "Alien Hash",
    "title": "AlienVault OTX",
    "parentId": "Hash",
    "contexts": ["selection"]
});

chrome.contextMenus.create({
    "id": "Hybrid Hash",
    "title": "Hybrid Analysis",
    "parentId": "Hash",
    "contexts": ["selection"]
});

chrome.contextMenus.create({
    "id": "Talos Hash",
    "title": "Talos",
    "parentId": "Hash",
    "contexts": ["selection"]
});

chrome.contextMenus.create({
    "id": "ThreatMiner Hash",
    "title": "ThreatMiner",
    "parentId": "Hash",
    "contexts": ["selection"]
});

chrome.contextMenus.create({
    "id": "URLhaus Hash",
    "title": "URLhaus",
    "parentId": "Hash",
    "contexts": ["selection"]
});

chrome.contextMenus.create({
    "id": "VT Hash",
    "title": "VirusTotal",
    "parentId": "Hash",
    "contexts": ["selection"]
});

chrome.contextMenus.create({
    "id": "X-Force Hash",
    "title": "X-Force",
    "parentId": "Hash",
    "contexts": ["selection"]
});

/*
 * URLs
 */
chrome.contextMenus.create({
    "id": "URL",
    "title": "URL",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "--All URL--",
    "title": "Open in all",
    "contexts": ["selection", "link", "image", "video", "audio"],
    "parentId": "URL"
});

chrome.contextMenus.create({
    "id": "BlueCoat URL",
    "title": "BlueCoat",
    "parentId": "URL",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "URLScan",
    "title": "URLScan",
    "parentId": "URL",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "URLVoid URL",
    "title": "URLVoid",
    "parentId": "URL",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "VT URL",
    "title": "VirusTotal",
    "parentId": "URL",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

/*
 * Malware URL
 */
chrome.contextMenus.create({
    "id": "Malware URL",
    "title": "Malware",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "Virussign",
    "title": "Virussign",
    "parentId": "Malware URL",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "Exploit-db",
    "title": "exploit-db",
    "parentId": "Malware URL",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "Malware Bazaar",
    "title": "Malware Bazaar",
    "parentId": "Malware URL",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "TrendMicro",
    "title": "TrendMicro",
    "parentId": "Malware URL",
    "contexts": ["selection", "link", "image", "video", "audio"]
});


chrome.contextMenus.create({
    "id": "ZoomEye",
    "title": "ZoomEye",
    "parentId": "Malware URL",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "Fofa",
    "title": "Fofa",
    "parentId": "Malware URL",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

/*
 * VPN
 */

chrome.contextMenus.create({
    "id": "VPN",
    "title": "VPN",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "Proxyium",
    "title": "Proxyium",
    "parentId": "VPN",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "Steganos",
    "title": "Steganos",
    "parentId": "VPN",
    "contexts": ["selection", "link", "image", "video", "audio"]
});

chrome.contextMenus.create({
    "id": "croxyproxy",
    "title": "croxyproxy",
    "parentId": "VPN",
    "contexts": ["selection", "link", "image", "video", "audio"]
});




// create empty url variable
var urls = [];

// create empty artifact variable
var artifact = "";

// Open all tabs flag variable
var fallthrough = false;

/*
 * Source:
 * https://stackoverflow.com/questions/13899299/write-text-to-clipboard#18258178
 * Note: Renamed function to match it's use case in Manifest V3
 */
function injectCopyStringToClipboard(str) {
    // Create new element
    var el = document.createElement("textarea");
    // Set value (string to be copied)
    el.value = str;
    // Set non-editable to avoid focus and move outside of view
    el.setAttribute("readonly", "");
    el.style = {position: "absolute", left: "-9999px"};
    document.body.appendChild(el);
    // Select text inside element
    el.select();
    // Copy text to clipboard
    document.execCommand("copy");
    // Remove temporary element
    document.body.removeChild(el);
}

/* 
 * New function using chrome.scripting to inject the copyStringToClipboard into current active tab.
 * This was the only "workaround" to having clipboards work in Manifest V3 since the Servcie Workers
 * no longer have access to the DOM in V3, which breaks all the old functionality.
 */
function copyStringToClipboard(str) {
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        var currTab = tabs[0];
        if (currTab) 
        {
            chrome.scripting.executeScript({
                target: {tabId: currTab.id},
                func: injectCopyStringToClipboard,
                args: [str],
            });
        }
    });
}

function sanitizeArtifact(artifact) {
    while(artifact.includes("[.]")) {
        artifact = artifact.replace("[.]", ".");
    }

    if(artifact.includes("hxxp://")) {
        artifact = artifact.replace("hxxp://", "http://");
    }

    if(artifact.includes("hxxps://")) {
        artifact = artifact.replace("hxxps://", "https://");
    }
    return artifact;
}

/*
 * The click event listener: 
 * where we perform the approprate action 
 * given the ID of the menu item that was clicked
 */
chrome.contextMenus.onClicked.addListener((info, tab) => {
    // identify context type and strip leading and trailing spaces
    if (info.selectionText) {
        artifact = String(info.selectionText).trim();
    } else if (info.linkUrl) {
        var link = new URL(info.linkUrl);
        artifact = link.host;
    } else if (info.srcUrl) {
        var src = new URL(info.srcUrl);
        artifact = src.host;
    }

    // unsanitize artifact if it is secured against clicking
    artifact = sanitizeArtifact(artifact);
    fallthrough = false;
    urls = [];

    // copy the selection to clipboard
    copyStringToClipboard(artifact);

    switch (info.menuItemId) {
            
            /*
             * IPs
             */

            case "--All AI--":
                fallthrough = true;
           
            case "Phind":
               urls.push("https://www.phind.com/search?q="+artifact);
               if (!fallthrough) { break; }
            
            case "You AI": 
                urls.push("https://you.com/search?q="+artifact);
                if (!fallthrough) { break; }
            
            case "Metaphor":
                urls.push("https://metaphor.systems/search?&q="+artifact);
                if (!fallthrough) { break; }

            case "Komo AI":
                urls.push("https://komo.ai/"+artifact);
            break;

            case "AndiSearch":
                urls.push("https://andisearch.com/"+artifact);
            break;

            case "Perplexity":
                urls.push("https://www.perplexity.ai/"+artifact);
            break;

            case "Yep AI":
                 urls.push("https://yep.com/web?q="+artifact);
                 if (!fallthrough) { break; }
            

            /*
             * IPs
             */
            
            case "--All IP--":
                fallthrough = true;

            case "AbuseIPDB":
                urls.push("https://www.abuseipdb.com/check/"+artifact);
                if (!fallthrough) { break; }

            case "Alien IP":
                urls.push("https://otx.alienvault.com/indicator/ip/"+artifact);
                if (!fallthrough) { break; }

            case "ARIN IP":
                urls.push("https://search.arin.net/rdap/?query="+artifact);
                if (!fallthrough) { break; }

            case "FortiGuard IP":
                urls.push("https://fortiguard.com/search?q="+artifact+"&engine=8");
                if (!fallthrough) { break; }

            case "GreyNoise IP":
                urls.push("https://viz.greynoise.io/ip/"+artifact);
                if (!fallthrough) { break; }

            case "IPinfo IP":
                urls.push("https://ipinfo.io/"+artifact);
                if (!fallthrough) { break; }

            case "IP Quality Score":
                urls.push("https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/"+artifact);
                if (!fallthrough) { break; }

            case "MX Toolbox ARIN IP":
                urls.push("https://www.mxtoolbox.com/SuperTool.aspx?action=arin%3a"+artifact);
                if (!fallthrough) { break; }

            case "Pulsedive IP":
                urls.push("https://pulsedive.com/indicator/?ioc="+btoa(artifact)); // btoa() = base64 encode
                if (!fallthrough) { break; }

            case "Scamalytics IP":
                urls.push("https://scamalytics.com/ip/"+artifact);
                if (!fallthrough) { break; }

            case "Talos IP":
                urls.push("https://talosintelligence.com/reputation_center/lookup?search="+artifact);
                if (!fallthrough) { break; }

            case "URLhaus IP":  /*promqna na categoriqta
                urls.push("https://urlhaus.abuse.ch/browse.php?search="+artifact);
                if (!fallthrough) { break; }

            /*
             * Domains
             */

            case "--All Domain--":
                fallthrough = true;

            case "BlueCoat Domain":
                urls.push("https://sitereview.bluecoat.com/#/lookup-result/"+artifact);
                if (!fallthrough) { break; }

            case "FortiGuard Domain": /*promqna v categoriqta malware
                urls.push("https://fortiguard.com/search?q="+artifact+"&engine=1");
                if (!fallthrough) { break; }
                */

            case "MX Toolbox Domain":
                urls.push("https://mxtoolbox.com/SuperTool.aspx?action=mx%3a"+artifact+"&run=toolpage");
                if (!fallthrough) { break; }

            case "Pulsedive Domain":
                urls.push("https://pulsedive.com/indicator/?ioc="+btoa(artifact)); // btoa() = base64 encode
                if (!fallthrough) { break; }

            case "URLhaus Domain":
                urls.push("https://urlhaus.abuse.ch/browse.php?search="+artifact);
                if (!fallthrough) { break; }
        

            /*
             * Hashes
             */
        
            case "--All Hash--":
                fallthrough = true;

            case "Alien Hash":
                urls.push("https://otx.alienvault.com/indicator/file/"+artifact);
                if (!fallthrough) { break; }

            case "Hybrid Hash":
                urls.push("https://www.hybrid-analysis.com/search?query="+artifact);
                if (!fallthrough) { break; }

            case "Talos Hash":
                urls.push("https://talosintelligence.com/talos_file_reputation");
                if (!fallthrough) { break; }

            case "ThreatMiner Hash":
                urls.push("https://www.threatminer.org/sample.php?q="+artifact);
                if (!fallthrough) { break; }

            case "URLhaus Hash":
                urls.push("https://urlhaus.abuse.ch/browse.php?search="+artifact);
                if (!fallthrough) { break; }

            case "VT Hash":
                urls.push("https://www.virustotal.com/#/file/"+artifact);
                if (!fallthrough) { break; }

            case "X-Force Hash":
                urls.push("https://exchange.xforce.ibmcloud.com/malware/"+artifact);
                break;

            /*
             * Malware URL
             */
            
            case "Exploit-db":
                urls.push("https://www.exploit-db.com/"+artifact);
                break;

            case "Virussign":
                urls.push("https://www.virussign.com/malware-scan/");
                if (!fallthrough) { break; }

            case "Malware Bazaar":
                urls.push("https://bazaar.abuse.ch/browse.php?search="+artifact);
                if (!fallthrough) { break; }

            case "TrendMicro":
                urls.push("https://www.trendmicro.com/vinfo/us/threat-encyclopedia/search/"+artifact);
                if (!fallthrough) { break; }
                    
            case "ZoomEye":
                urls.push("https://www.zoomeye.org/");
                if (!fallthrough) { break; }

            case "Fofa":
                urls.push("https://en.fofa.info/");
                if (!fallthrough) { break; }
             
            /*
             * VPN
             */
            
            case "Proxyium":
                urls.push("https://proxyium.com/");
                if (!fallthrough) { break; }

            case "Steganos":
                urls.push("https://www.steganos.com/en/free-online-web-proxy");
                if (!fallthrough) { break; }

            case "croxyproxy":
                urls.push("https://www.croxyproxy.com/");
                if (!fallthrough) { break; }

            
    

            /*
             * URLs
             */

            case "--All URL--":
                fallthrough = true;

            case "BlueCoat URL": 
                urls.push("https://sitereview.bluecoat.com/#/lookup-result/");
                if (!fallthrough) { break; }

            case "URLScan": 
                urls.push("https://urlscan.io/");
                if (!fallthrough) { break; }

            case "URLVoid URL":
                urls.push("https://urlvoid.com/scan/"+artifact);
                if (!fallthrough) { break; }
            
            case "VT URL": 
                urls.push("https://www.virustotal.com/#/home/url");
                if (!fallthrough) { break; }


    }

    // Open one or all tabs
    urls.forEach((url) => {
        chrome.tabs.create({url});
    });
});
