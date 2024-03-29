var menuId = chrome.contextMenus.create({
  title: "OSINT=*",
  id: "parent",
  contexts: [ "selection" ],
  onclick: main,
})

const osint_urls = {
  abuseipdb: `https://www.abuseipdb.com/check/`,
  greynoise: `https://www.greynoise.io/viz/ip/`,
  hybridanalysis: `https://www.hybrid-analysis.com/search?query=`,
  ibmxforce: `https://exchange.xforce.ibmcloud.com/search/`,
  ipinfo: `https://ipinfo.io/widget/demo/`,
  shodan: `https://www.shodan.io/search?query=`,
  talosintelligence: `https://talosintelligence.com/reputation_center/lookup?search=`,
  virustotal: `https://www.virustotal.com/gui/search/`,
  viewdns: 'https://viewdns.info/reverseip/?host=',
  whoisdomaintools: 'https://whois.domaintools.com/',
  urlvoid: 'https://www.urlvoid.com/scan/',
  mxtoolbox: 'https://mxtoolbox.com/SuperTool.aspx?action=mx%3a',
  webcheck: 'https://web-check.as93.net/results/https%3A%2F%2F',
  scamalytics: 'https://scamalytics.com/ip/',
  ipvoid: 'https://www.ipvoid.com/ip-blacklist-check/', //manual
  cyberchef: 'https://gchq.github.io/CyberChef/'
};


function main(info, tab) {
	// get highlighted text
	var IOC = info.selectionText;

	// replace "[dot]" with "."
	IOC = IOC.replace(/\[dot\]/g, '.');

	// remove whitespace, quotes, brackets
	IOC = IOC.replace(/[\"\'\[\] ]/g, '');

	// regex check if IOC is md5, sha1, sha256 hash
	var ishash = !IOC.search(/\b[A-Fa-f0-9]{32,64}\b/);

	// regex check if IOC is IPv4 address
	var isIPv4 = !IOC.search(/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/);

	if (ishash){ // search hash OSINT sources
    var urls = [];
    var default_sources = ['virustotal', 'talosintelligence', 'ibmxforce', 'hybridanalysis', 'cyberchef']; //These are used if options are not set (ex: first time user)

    chrome.storage.sync.get({filehash_osint_sources: default_sources,}, function(items) {
      items.filehash_osint_sources.forEach(function (item, index) { // Iterate every OSINT source you have selected
        urls.push(osint_urls[item] + IOC);
      });
      chrome.windows.create({ // Create the windows with the OSINT URLs
        url: urls,
        incognito: false,
      });
    });
	}
	
  else if (isIPv4){ // search IPv4 OSINT sources
    var urls = [];
    var default_sources = ['virustotal', 'abuseipdb', 'ipvoid', 'talosintelligence', 'ibmxforce', 'ipinfo', 'greynoise', 'shodan', 'viewdns', 'scamalytics','cyberchef'];

    chrome.storage.sync.get({ip_osint_sources: default_sources,}, function(items) {
      items.ip_osint_sources.forEach(function (item, index) {
        if(osint_urls[item] == 'https://viewdns.info/reverseip/?host=')
          {
            urls.push(osint_urls[item] + IOC + '&t=1');
          }
        else if(osint_urls[item] == 'https://www.ipvoid.com/ip-blacklist-check/')
          {
            urls.push(osint_urls[item]);
          }
        else if(osint_urls[item] == 'https://gchq.github.io/CyberChef/')
          {
            urls.push(osint_urls[item]);
          }
        else
          {
            urls.push(osint_urls[item] + IOC);
          }
        
      });
      chrome.windows.create({
        url: urls,
        incognito: false,
      });
    });
	}

	else{ // assume IOC is domain name, search domain name OSINT sources
    var urls = [];
    var default_sources = ['abuseipdb', 'virustotal', 'talosintelligence', 'ibmxforce', 'shodan', 'viewdns', 'whoisdomaintools', 'urlvoid', 'mxtoolbox', 'webcheck', 'cyberchef'];

    chrome.storage.sync.get({domain_osint_sources: default_sources,}, function(items) {
      items.domain_osint_sources.forEach(function (item, index) {
        if(osint_urls[item] == 'https://mxtoolbox.com/SuperTool.aspx?action=mx%3a')
        {
            urls.push(osint_urls[item] + IOC + '&run=toolpage');
        }
        else if(osint_urls[item] == 'https://gchq.github.io/CyberChef/')
        {
          urls.push(osint_urls[item]);
        }
        else if(osint_urls[item] == 'https://viewdns.info/reverseip/?host=')
        {
          urls.push(osint_urls[item] + IOC + '&t=1');
        }
        else urls.push(osint_urls[item] + IOC);
      });
      chrome.windows.create({
        url: urls,
        incognito: false,
      });
    });
	}
}
