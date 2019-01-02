import requests
import json
import urllib
import logging
import sys
import time

import splunk.search
from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(["etc", "apps", "SA-Utils", "lib"]))
from SolnCommon.log import setup_logger
from SolnCommon.modinput import JsonModularInput
from SolnCommon.modinput import Field, BooleanField, IntegerField, RangeField
from SolnCommon.kvstore import KvStoreHandler
from SolnCommon.credentials import CredentialManager
from SolnCommon.pooling import should_execute

class FacebookThreatExchange(JsonModularInput):
    '''
        Modular Input for interacting with the Facebook Threat Exchange.
    '''
    FB_TX_VERSION = 'v2.5'
    THREAT_INDICATOR_URL = 'https://graph.facebook.com/' + FB_TX_VERSION + '/threat_descriptors?'
    ## Custom User-Agent to track adoption rate.
    REQUEST_HEADERS = {'User-Agent': 'SplunkIntegration/[1.0]'}

    APP = "Splunk_DA-ESS_FacebookThreatExchange"
    OWNER = "nobody"

    FB_TX_OPTIONS = {
       "owner": OWNER,
       "app": APP,
       "collection": "fb-tx-collection"
    }

    DEFAULT_TIMEOUT = 120
    LOOKUP_GEN_SEARCHES = [
        "FB-TX - IP Intel - Lookup Gen",
        "FB-TX - Domain Intel - Lookup Gen",
        "FB-TX - HTTP Intel - Lookup Gen",
        "FB-TX - Email Intel - Lookup Gen",
        "FB-TX - File Intel - Lookup Gen",
        "FB-TX - Registry Intel - Lookup Gen",
        "FB-TX - Unmatchable Intel - Lookup Gen"
    ]

    def __init__(self):
        scheme_args = {'title': "Facebook Threat Exchange",
                       'description': "Enables consumption of Threat Intelligence from the Facebook Threat Exchange",
                       'use_external_validation': "true",
                       'streaming_mode': "json",
                       'use_single_instance': "true"
                       }
        args = [
            #General Options
            Field("type", "IndicatorType", "The IndicatorType to collect. Leaving blank collects all IndicatorTypes.", False, False),
            Field("app_id", "App-ID", "Threat Exchange App-ID (Note: app_secret must be kept in Credential Manager.", True, True),
            Field("since", "Since", "A Unix timestamp or PHP-style strtotime data value that points to the start of the range of time-based data.", True, True),
            BooleanField("include_expired", "Include Expired?", "When set to true, expired intel will also be collected."),
            RangeField("limit", "Limit", "Maximum number of results per API request. (1-1000)", 1, 1000, True, True),
            IntegerField("request_limit", "API Request Limit", "Maximum number of subsequent API requests per stanza per Modular Input execution.", True, True),
            RangeField("max_confidence", "Max Confidence", "Maximum allowed confidence value for the intel returned. (0 - 100).", 0, 100, True, True),
            RangeField("min_confidence", "Min Confidence", "Minimum allowed confidence value for the intel returned. (0 - 100).", 0, 100, True, True)
            ]

        self._app = self.APP
        self._owner = self.OWNER
        self._name = 'Facebook Threat Exchange'

        self._logger = setup_logger(name='fb_threat_exchange', level=logging.INFO)

        super(FacebookThreatExchange, self).__init__(scheme_args, args)

    def run_lookup_generating_searches(self):
        '''
            Run the lookup generating searches responsible for moving the
            Facebook Threat Exchange Intel from the fb-tx-collection KV
            Collection to the FB-TX threatlist lookups.
        '''
        log_format = 'Facebook Threat Exchange - search="%s" sid="%s" elapsed="%s" action="dispatching" message="%s"'
        self._logger.info(log_format, "", "", "", "Dispatching FB-TX update searches...")
        for search in self.LOOKUP_GEN_SEARCHES:
            try:
                job = splunk.search.dispatchSavedSearch(search, self._input_config.session_key)
                self._logger.info(log_format, search, job.sid, "", "Dispatched FB-TX update search")

                elapsed = 0
                while not job.isDone and elapsed < self.DEFAULT_TIMEOUT:
                    time.sleep(1)
                    elapsed += 1

                if elapsed > self.DEFAULT_TIMEOUT:
                    self._logger.warning(log_format, search, job.sid, elapsed, "FB-TX update search timed out - intelligence may be incomplete.")
                else:
                    self._logger.info(log_format, search, job.sid, elapsed, "FB-TX update search completed.")
            except Exception as e:
                self._logger.exception(log_format, search, "", "", "Unable to dispatch search.")

    def run(self, stanzas, *args, **kwargs):
        ## Determine if we should execute this modular input based on SHP/SHC configuration.
        exec_status, exec_status_msg = should_execute(session_key=self._input_config.session_key)
        if not exec_status:
            self._logger.debug('Facebook Threat Exchange - stanza="" app_id="" action="initializing" success="" message="Execution not permitted: %s"', exec_status_msg)
        else:
            for stanza in stanzas:
                stanza_name = stanza.get('name')
                app_id = stanza.get('app_id', '')
                log_format = 'Facebook Threat Exchange - stanza="' + stanza_name + '" app_id="' + app_id + '" action="%s" success="%s" message="%s"'
                self._logger.info(log_format, 'initializing', '', 'Execution permitted, initializing Modular Input...')

                request_limit = stanza.get('request_limit')

                ## Get App Secret from Credential Manager
                self._logger.debug(log_format, 'initializing', '', 'Retrieving app_secret from Credential Manager...')
                credmgr = CredentialManager(self._input_config.session_key)
                app_secret = credmgr.get_clear_password(app_id, '', self.APP, self.OWNER)

                ## Build FB-TX API Query
                query_params = urllib.urlencode({
                    'access_token': app_id + '|' + app_secret,
                    'type': stanza.get('type', ''),
                    'since': stanza.get('since', 'yesterday'), ## Required field for FB-TX API
                    'include_expired': stanza.get('include_expired', False),
                    'limit': stanza.get('limit', ''), ## FB-TX API will default this to 25 if unspecified.
                    'max_confidence': stanza.get('max_confidence', ''),
                    'min_confidence': stanza.get('min_confidence', '')
                })
                uri = self.THREAT_INDICATOR_URL + query_params

                ## Begin Polling the FB-TX API for intel.
                request_count = 0
                while request_count < request_limit:
                    try:
                        ## 1 - Make HTTP Request
                        self._logger.info(log_format, 'polling', '', "Polling FB Threat Exchange...")
                        r = requests.get(uri, headers=self.REQUEST_HEADERS)

                        ## 2 - Attempt to load result JSON
                        if r.status_code != 200:
                            self._logger.error(log_format, 'polling', '0', "The FB-TX Server responded with something other than an HTTP 200. Received an HTTP " + str(r.status_code))
                        results = json.loads(r.text)

                        ## 3 - Send data to KV Store
                        # Even with no results, the server should return { data: [] }
                        if 'data' not in results:
                            self._logger.debug(log_format, 'polling', '0', "No 'data' attribute found in results")
                            ## Check for error from FB-TX API
                            if 'error' in results:
                                self._logger.error(log_format, 'polling', '0', "FB-TX API returned the following error object: " + str(results['error']))
                            break
                        self._logger.debug(log_format, 'saving', '', "Saving Intel to Splunk FB-TX Collection")

                        ## 3a - Move 'id' to '_key' field
                        # Max result size is 1000 so this will never iterate over more than 1000 records at a time.
                        for indicator in results['data']:
                            indicator['_key'] = indicator['id']
                            del indicator['id']

                        ## 3b - Write records to the 'fb-tx-collection' KV Store collection
                        session_key = self._input_config.session_key
                        response, content = KvStoreHandler.batch_create(results['data'], session_key, self.FB_TX_OPTIONS, True, 'time')
                        if response.status == 200:
                            records_received_count = len(results['data'])
                            records_saved_count = len(json.loads(content))
                            self._logger.info(log_format, 'saving', '1', str(records_saved_count) + " FB-TX Intel records were written to the Splunk FB-TX Collection")
                            if records_saved_count < records_received_count:
                                self._logger.warning(log_format, 'saving', '1', str(records_received_count) + " records were received from the Facebook Threat Exchange and only " + str(records_saved_count) + " were written to the Splunk FB-TX Collection")
                        else:
                            self._logger.error(log_format, 'saving', '0', "There was an issue writing data to the Splunk FB-TX Collection. The server responded with an HTTP " + str(response.status))

                        ## 4 - Determine if we've hit our request limit, if not, are there additional pages to collect?
                        if request_count == request_limit - 1:
                            self._logger.info(log_format, 'complete', '1', "Hit API request limit of " + str(request_limit) + ". Concluding FB-TX collection.")
                            break;
                        elif 'paging' in results and 'next' in results['paging']:
                            ## Update URI
                            uri = results['paging']['next']

                            ## Increment request count
                            request_count += 1
                            self._logger.info(log_format, 'saving', '', "Requesting next page of results...")
                        else:
                            self._logger.info(log_format, 'complete', '1', "Finished consumption of FB-TX intel.")
                            break
                    except ValueError as value_error:
                        self._logger.exception(log_format, '', '0', "A ValueError occurred: " + str(value_error))
                        break
                    except Exception as e:
                        self._logger.exception(log_format, '', '0', "An Unknown Exception occurred - Exception: " + str(e))
                        break


                self._logger.info(log_format, 'complete', '1', "Collection of FB TX Intel data is now finished!")

            ## Dispatch FB-TX Lookup Gen Searches
            self.run_lookup_generating_searches()

if __name__ == '__main__':
    modinput = FacebookThreatExchange()
    modinput.execute()
