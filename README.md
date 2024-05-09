# api-examples
Examples for Scribe Security's API in the form of Postman environment and collection json files.

### Setup
To use the examples you'll need to set your api token in the API Environment file.

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
    - python api-python-examples.py --api_call <api-to-execute> --api_token <your_api_token>
* Flags:
   * --api_call: this specifies which api to call
      * component-vulnerabilities 
      * get-products
  * --api_token: this is your scribe api token (obtained from the integrations page on your scribe account)
* EXAMPLE RUN:
    * python api-python-examples.py --api_call component-vulnerabilities --api_token <your_api_token> 
        * Results will be in a file called vulnerabilities_report.json
    * python api-python-examples.py --api_call get-products --api_token <your_api_token>
        * Results will be in a file called products_report.json 

