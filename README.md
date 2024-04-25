# api-examples
Examples for Scribe Security's API in the form of Postman environment and collection json files.

### Setup
To use the examples you'll need to set your client ID and client secret in the API Environment file.

## Usage
Before running requests you'll need to get an access token by clicking on "Get New Access Token" in the "Scribe API" collection.

Get an access token with the "Get Token" request. 
The access token will be stored as an environment variable and used in subsequent requests.

Get a list of all available datasets with the "Get Datasets" request. 
All datasets will be stored as an environment variables in the format of "dataset_<dataset>", with spaces replaced with underscores.
The sample queries provided use these dataset variables.
The "Query API" request is a skeleton request for crafting your own data queries.

## Sample Queries
All sample queries include optional filters for product, version, and component 
(the "Query components" request doesn't include the component filter).
To use one or more of these filters set the corresponding collection variable in the "Scribe API" collection to the desired value.

* Query Outdated dependencies - queries for outdated dependencies with OSSF score >= 3 or above and maintenance score >= 3.
* Query Vulnerabilities - queries for vulnerabilities with severity >= 6.
* Query SBOMs - queries for image and source (git) SBOMs.
* Query Attestation Context - queries for attestations by key:value pairs in the attestation context. 
Uses the "context_element" collection variable.
* Query Components - queries for the list of components.
* Query Licenses - queries for the list of licenses.

## Running Python examples
* First make sure to install the dependencies required in requirements.txt
* There are 2 api calls available 
    1. Get vulnerabilities for components 
    2. Get the products for your team 
* Both calls return the data as json as follows
    * Get vulnerabilities for components -> vulnerabilities_report.json
    * Get the products for your team ->  products_report.json
* Running the script 
    - python api-python-examples.py --api_call <api-to-execute> --client_id <client-id> --client_secret <client-secret>
* Flags:
   * --api_call: this specifies which api to call
      * component-vulnerabilities 
      * get-products
  * --client_id: this is your scribe client id (obtained from the integrations page on your scribe account)
  * --client_secret: this is your scribe client secret (obtained from the integrations page on your scribe account)
* EXAMPLE RUN:
    * python api-python-examples.py --api_call component-vulnerabilities --client_id <your_client_id> --client_secret <your_client_secret>
        * Results will be in a file called vulnerabilities_report.json
    * python api-python-examples.py --api_call get-products --client_id <your_client_id> --client_secret <your_client_secret>
        * Results will be in a file called products_report.json 

