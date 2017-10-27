import logging
import sys

if sys.version_info[0] == 2: # Python 2
    import xmlrpclib
else:
    import xmlrpc.client as xmlrpclib

class IP360:
    def __init__(self, url=None, username=None, password=None, logfile=None, loglevel=logging.INFO):
        if logfile:
              logging.basicConfig(filename=logfile, level=loglevel)
        else:
              logging.basicConfig(level=loglevel)
        if url and username and password:
            logging.info("Setting up connection to VnE %s with username %s..." % (url, username))
            self.server = xmlrpclib.ServerProxy(url)
            try:
                self.sessionID = self.server.login(2, 0, username, password)
                self.url = url
            except Exception as e:
                logging.critical("Couldn't set up connection to VnE: : %s" % e)
                raise Exception(e)
        else:
            logging.critical("Not all credentials are specified")
            raise Exception("Invalid credentials specified")

    ####################
    # Server functions #
    ####################
    def logout(self):
        logging.info("Closing VnE connection...")
        try:
            self.server.logout(self.sessionID)
        except Exception as e:
            logging.error("Could not log out: %s" % e)
            raise Exception(e)
        self.sessionID = None


    def _xml_call(self, obj, action, params):
        try:
            return self.server.call(self.sessionID, obj, action, params)
        except xmlrpclib.Fault as e:
            logging.error("Error performing call: %s" % e)
            raise Exception(e)
        except Exception as e:
            logging.error("Error performing call: %s" % e)
            raise Exception(e)


    def call(self, obj, action, params):
        logging.debug("Making call with object=%s action=%s params=%s" % (obj, action, params))
        if action.lower() in ['fetch', 'search']:
            params['offset'] = 0
            params['limit'] = 100000
            headers = None
            results = []
            while 1==1:
                result = self._xml_call(obj, action, params)
                
                params['offset'] += params['limit']
                if params.get('format', 'list') == 'table':
                    results += result['table']
                    if len(result['table']) == 0:
                        headers = result['columns']
                        break
                else:
                    results += result
                    if len(result) == 0: break
            if params['format'] == 'table':
                return {'columns': headers,
                          'table':   results}
            else:
                return results
        else:
            return self._xml_call(obj, action, params)

    #########
    # Hosts #
    #########
    def getHosts(self):
        hosts = dict()
        logging.info("Retrieving list of hosts...")
        result = self.call('class.Host', 'fetch', {'format':'table', 'attributes':['id', 'ipAddress']})
        for row in result['table']:
              hosts['Host.' + str(row[result['columns'].index('id')])] = row[result['columns'].index('ipAddress')]
        return hosts

    #################
    # Scan Profiles #
    #################
    def getScanProfiles(self):
        scanprofiles = dict()
        logging.info("Retrieving list of scan profiles...")
        result = self.call('class.ScanProfile', 'fetch', {'format':'table', 'attributes':['id', 'name']})
        for row in result['table']:
              scanprofiles['ScanProfile.' + str(row[result['columns'].index('id')])] = row[result['columns'].index('name')]
        return scanprofiles


    def getScanProfile(self, name):
        logging.info('Retrieving scan profiles "%s"...'%name)
        return self.call('class.ScanProfile', 'search', {'format':'list', 'query':"name='%s'"%name})[0]

    ###################
    # Vulnerabilities #
    ###################
    def getVulnerabilities(self):
        vulnerabilities = dict()
        logging.info("Retrieving list of vulnerabilities...")
        result = self.call('class.Vuln', 'fetch', {'format':'table', 'attributes':['id', 'name']})
        for row in result['table']:
            vulnerabilities['Vuln.' + str(row[result['columns'].index('id')])] = row[result['columns'].index('name')]
        result = self.call('class.CustomVuln', 'fetch', {'format':'table', 'attributes':['id', 'name']})
        for row in result['table']:
            vulnerabilities['Vuln.' + str(row[result['columns'].index('id')])] = row[result['columns'].index('name')]
        return vulnerabilities

    def getVulnResultsForAudit(self, audit):
        return self.call('class.VulnResult', 'search', {'format':'table', 'query':"audit='%s'"%audit,
                                                        'attributes':['audit', 'host', 'vuln', 'detailBody']})

    ############
    # Networks #
    ############
    def getNetworks(self):
        networks = {}
        logging.info("Retrieving list of networks...")
        result = self.call('class.Network', 'fetch', {'format':'table', 'attributes':['id', 'name']})
        for row in result['table']:
              networks['Network.' + str(row[result['columns'].index('id')])] = row[result['columns'].index('name')]
        return networks


    def getNetwork(self, name):
        logging.info('Retrieving network "%s"...' % name)
        return self.call('class.Network', 'search', {'format':'list', 'query':"name='%s'"% name})[0]


    def addNetwork(self, name):
        logging.info('Adding network "%s"...' % name)
        return self.call('class.Network', 'create', {'name':name})


    def deleteNetwork(self, netw_id):
        if not netw_id.startswith("Network."):
            logging.warning('"%s" is not a valid network. Not deleting...' % netw_id)
            return False
        logging.info('Deleting network "%s"...' % netw_id)
        self.call(netw_id, 'delete', {})
        return True


    def addNetworkIncludes(self, netw_id, ip_list):
        logging.info('Adding %s to the includes list of network "%s"' % ())
        self.call(netw_id, 'addIncludes', {'addrs': ip_list})

    ##########
    # Audits #
    ##########
    def getAuditsForNumberOfDays(self, days=7):
        logging.info("Retrieving scan results from the past %s days..." % days)
        timedelta = str(int(time.mktime((datetime.datetime.now()-datetime.timedelta(days=days)).timetuple())))
        return self.call('class.Audit', 'search', {'format':'list','query':"endTime > %s" % timedelta})

    ####################
    # Device Profilers #
    ####################
    def getDeviceProfiler(self, name):
        logging.info('Retrieving device profiler "%s"...' % name)
        return self.call('class.DP', 'search', {'format':'list', 'query':'name=\'' + name + '\''})[0]

    #####################
    # Scan Manipulation #
    #####################
    def startScan(self, deviceProfiler, network, scanProfile):
        logging.info('Starting scan of network "%s"...' % network)
        return self.call(deviceProfiler, 'startScan', {'network':network, 'scanProfile':scanProfile})

    def stopScan(self, audit):
        logging.info('Stopping scan "%s"...' % audit)
        return self.call('class.DP', 'cancelScan', {'audit':audit})

    def getScanStatus(self, audit):
        logging.info('Retrieving status of scan "%s"...'%name)
        return self.call(audit, 'getAttribute', {'attribute':'status'})

    def getScanStatusTypes(self):
        logging.info("Retrieving scan status types")
        return self.call('SESSION', 'getEnumValues', {'name':'AuditStatus'})

