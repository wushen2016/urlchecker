import sys
import urllib
import subprocess
import random
import string
from URLChecker import *
from URLChecker_Util import *

rand_str = string.lowercase + string.digits
def generateRandomString(length):
    return ''.join(random.choice(rand_str) for i in xrange(length))

class URLChecker_Stat:
    '''
    some statistics for a batch of urls.
    now it only contains domain_hosts:
    1) domain_hosts
    2) some features maybe helpful to define suspicious domain
    3) suspicious domain
    '''

    def __init__(self):
        self.urlchecker = URLChecker()
        self.url_util = URLChecker_Util()
        
        self.d_domain_hosts = {}
        self.d_hostInAlexaTop_urls = {}
        
        self.s_suspiciousDomain = set()

    def dumpSuspicious_Domain_Hosts(self, filename):
        '''
        1) statistics about domain_hosts
        2) define suspicious domain rule

        yes, what we here defined is DOMAIN SUSPICIOUS,
            but considerring domain and its hosts


        yes, yes, it may be not useless, who knows,
        '''
        self.doStat_Domain_Hosts(filename)
        
        fw_suspicious = open(filename + "_suspicious.txt", "wb")
        for domain, hostInfo in self.d_domain_hosts.iteritems():
            if hostInfo['isInAlexaTop'] or hostInfo['isip']:
                continue

            #define your own suspicious rule
            
        fw_suspicious.close()
            
    def doStat_Domain_Hosts(self, filename):
        '''
        some statistics about urls within a file.
        1) domain_hosts
        2) some feature maybe useful to define suspicious
        '''
        if self.d_domain_hosts:
            return
    
        fr = open(filename, 'rb')
        for line in fr:
            url = urllib.unquote(line.strip())
            
            try:
                host, port, subhost, domain, tld, isip, isvaliddomain = self.urlchecker.getHostInfo(url)
                host[0]
            except:
                continue
            
            isInAlexaTop = self.url_util.isDomainInAlexTop(domain)
            
            if domain not in self.d_domain_hosts:
                self.d_domain_hosts[domain] = {'isip':isip, 
                                               'isvaliddomain' : isvaliddomain,
                                               'isInAlexaTop': isInAlexaTop,
                                               'cnt_hosts': 0,
                                               'host_max_len' : len(host),
                                               'host_min_len' : len(host),
                                               'sub_max_len' : 0,
                                               'hosts' : set(),
                                               'cnt_urls' : 0,  #all the urls count for this domain
                                               'urls' : set(),  #only one for each filetype
                                               'filetype': set(),
                                               'cnt_filetype' : 0,
                                               'percent_part_host': 0.0,
                                               'percent_host_url': 0.0
                                               }
            self.d_domain_hosts[domain]['hosts'].add(host)
            self.d_domain_hosts[domain]['sub_max_len'] = max(self.d_domain_hosts[domain]['sub_max_len'], max(map(len, subhost.split('.'))))
            self.d_domain_hosts[domain]['cnt_urls'] += 1
            
            filetype = self.url_util.getFileType(url)
            if filetype not in self.d_domain_hosts[domain]['filetype']:
                self.d_domain_hosts[domain]['filetype'].add(filetype)
                self.d_domain_hosts[domain]['cnt_filetype'] += 1
                self.d_domain_hosts[domain]['urls'].add(url)
                
                max_hostpart = max(map(len, host.split('.')))
                self.d_domain_hosts[domain]['percent_part_host'] = max_hostpart * 1.0 / len(host)
                self.d_domain_hosts[domain]['percent_host_url'] = len(host) * 1.0 / len(url)
                
            if isip or not isInAlexaTop:
                continue
                
            #deal with alexa top
            directInAlexaTop = self.url_util.isDirectInAlexTop(domain, host)
            inAlexaTop = 'direct'
            if (not directInAlexaTop):
                inAlexaTop = 'indirect'
                
            if host not in self.d_hostInAlexaTop_urls:
                self.d_hostInAlexaTop_urls[host] = {'domain' : domain,
                                                    'inAlexa' : inAlexaTop,
                                                    'urls' : set()}
            self.d_hostInAlexaTop_urls[host]['urls'].add(url)
        fr.close()
        
        for domain in self.d_domain_hosts:
            self.d_domain_hosts[domain]['cnt_hosts'] = len(self.d_domain_hosts[domain]['hosts'])
            self.d_domain_hosts[domain]['host_max_len'] = max(map(len, self.d_domain_hosts[domain]['hosts']))
            self.d_domain_hosts[domain]['host_min_len'] = min(map(len, self.d_domain_hosts[domain]['hosts']))   
            
    def dumpStat_Domain_Hosts(self, filename):
        self.doStat_Domain_Hosts(filename)
        
        fw_domain_hosts = open(filename + '_stat_domain_hosts.txt', 'wb')
        sorted_domain_hosts = sorted(self.d_domain_hosts.items(), key=lambda item: len(item[1]['hosts']), reverse=True)
        for item in sorted_domain_hosts:
            domain = item[0]
            hostInfo = item[1]
            
            if hostInfo['isip'] or hostInfo['isInAlexaTop']:
                continue
            
            black = ''
            if domain in self.s_suspiciousDomain:
                black = 'black'
            hdrAry = [black, domain, hostInfo['cnt_hosts'], hostInfo['cnt_urls'], hostInfo['cnt_hosts'] * 1.0 / hostInfo['cnt_urls'],
                      hostInfo['host_max_len'], hostInfo['host_min_len'], hostInfo['host_min_len'] * 1.0 / hostInfo['host_max_len'],
                      hostInfo['sub_max_len'], hostInfo['sub_max_len'] * 1.0 / hostInfo['host_max_len'],
                      hostInfo['percent_part_host'], hostInfo['percent_host_url'], 
                      hostInfo['cnt_filetype'],
                      hostInfo['isvaliddomain'], '_domain_'
                    ]
            hdrAry[2:-1] = map(str, hdrAry[2:-1])
            
            if hostInfo['cnt_filetype'] < 10:
                hdrAry.append('\t'.join(hostInfo['filetype']))
            
            fw_domain_hosts.write("%s\n"%('\t'.join(hdrAry)))
            for host in hostInfo['hosts']:
                fw_domain_hosts.write("\t%s\n"%host)
            for url in hostInfo['urls']:
                fw_domain_hosts.write("\t%s\n"%url)
        fw_domain_hosts.close()

    def doSimpleStat(self, filename):
        '''
        do statistics about all the urls within filename,

        filename.txt
            ==> filename.txt_domain.txt             all domains within filename.txt
                filename.txt_domain_hosts.txt       domain and its hosts info within filename
                filename.txt_white_direct.txt       all urls whose host is directly in alex_top_1m, there are absolute safe
                filename.txt_white_indirect.txt     all urls whose host is indirectly in alex_top_1m, there are probably safe
                filename.txt_black.txt              all urls whose host is not in alex_top_1m, there are unknown, gray, or black
                                                        need to be checked
        '''
        fw_white_direct = open(filename + '_white_direct.txt', 'wb')
        fw_white_indirect = open(filename + '_white_indirect.txt', 'wb')
        fw_unknown = open(filename + '_unknown.txt', 'wb')

        d_domain_hosts = {} # {domain:[hosts, hosts,...]}
        with open(filename, 'rb') as fr:
            for line in fr:
                #php%3Fmod%3Dtag%26id%3D3543.	1	_domain_	_invalid_
                #    bbs.hg707.com%2Fmisc.php%3Fmod%3Dtag%26id%3D3543
                line = urllib.unquote(line.strip())
            
                host, port, subhost, domain, tld, isip, isvalidDomain = self.urlchecker.getHostInfo(line)
                d_domain_hosts.setdefault(domain, set()).add(host)

                info = line.strip() + '\t' + domain + '\t' + host + '\tisip\n'
                if not isip:
                    info = line.strip() + '\t' + domain + '\t' + host + '\tnotip\n'
                    
                if self.url_util.isDirectInAlexTop(domain, host):
                    fw_white_direct.write(info)
                elif self.url_util.isIndirectInAlexTop(domain, host):
                    fw_white_indirect.write(info)
                else:
                    fw_unknown.write(info)
        fw_white_direct.close()
        fw_white_indirect.close()
        fw_unknown.close()
            
        fw_domain = open(filename + '_domain.txt', 'wb')    
        fw_domain_hosts = open(filename + '_domain_hosts.txt', 'wb')
        fw_hosts = open(filename + '_hosts.txt', 'wb')
        sorted_domain_hosts = sorted(d_domain_hosts.items(), key=lambda item: len(item[1]), reverse=True)
        for item in sorted_domain_hosts:
            domain = item[0]
            hosts = item[1]
            invalidHit = '\n'
            if domain[0] == '.' or domain[-1] == '.':
                invalidHit = '\t_invalid_\n' 
                                
            fw_domain.write('%s%s'%(domain, invalidHit))
            fw_domain_hosts.write('%s\t%d\t_domain_%s'%(domain, len(hosts), invalidHit))
            
            for host in d_domain_hosts[domain]:
                fw_domain_hosts.write('\t%s\n'%host)
                fw_hosts.write(host + '\n')
                
        fw_domain.close()
        fw_domain_hosts.close()
        fw_hosts.close()

def main():
    obj = URLChecker_Stat()
    #obj.doSimpleStat(sys.argv[1])
    #obj.doStat_Domain_Hosts(sys.argv[1])
    #obj.dumpStat_Domain_Hosts(sys.argv[1])
    obj.dumpSuspicious_Domain_Hosts(sys.argv[1])

if __name__ == "__main__":
    main()
