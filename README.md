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
All sample queries include optional filters for product, version, and component.
To use one or more of these filters set the corresponding collection variable in the "Scribe API" collection to the desired value.

* Query Outdated dependencies - queries for outdated dependencies with OSSF score >= 3 or above and maintenance score >= 3
* Query Vulnerabilities - queries for vulnerabilities with severity >= 6
* Query SBOMs - queries for image and source (git) SBOMs
