
[fb_threat_exchange://default]
* Configure an input for consumption of Facebook Threat Exchange Intel.

type            = <string>
* The Facebook Threat Exchange IndicatorType to be collected. Leaving this
* value blank will result in the collection of all IndicatorTypes. For a 
* list of IndicatorTypes, please see: 
*
*   https://developers.facebook.com/docs/threat-exchange/reference/apis/indicator-type/v2.5

app_id          = <string>
* The App-ID to be used in association with your App-Secret to interact with
* the Facebook Threat Exchange API. If you do not have one, you can follow
* the following link to begin the application process:
*
*   https://developers.facebook.com/products/threat-exchange
*
* Note that the modular input will reference your App-Secret from the 
* Credential Manager using your App-ID. For this to work properly, you must 
* have the following configuration in the Credential Manager:
*
*   User:           <app_id>
*   Password:       <app_secret>
*   Realm:          <blank>
*   Application:    Splunk_DA-ESS_FacebookThreatExchange

since           = <string>
* A Unix timestamp or PHP strtotime data value that points to the start of the 
* range of time-based data. For information related to valid strtotime values
* please see:
*
*   http://php.net/manual/en/function.strtotime.php

include_expired = <bool>
* When set to true, expired intel will be collected as well. Note that expired
* intel will not be used for matching against Splunk events.

limit           = <integer>
* The maximum number of results returned per API request. The Facebook Threat 
* Exchange limits this to 1000.  

request_limit   = <integer>
* The maximum number of API requests the Modular Input is allowed to initiate
* against the Facebook Threat Exchange per stanza per execution.

max_confidence  = <integer>
* Maximum allowed confidence value, between 0 and 100, for intel returned by 
* the Facebook Threat Exchange.

min_confidence  = <integer>
*Minimum allowed confidence value, between 0 and 100, for intel returned by 
* the Facebook Threat Exchange.
