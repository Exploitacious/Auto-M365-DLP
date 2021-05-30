# Auto-M365-DLP
MSP Focused DLP deployment template for M365 Business Premium clients.

The point of this is to deploy an intelligent implementation of DLP on a customer's environment with a simple powershell script, rather than spending hours clicking through the protection.office.com GUI. There are a few things to consider in this script, but it was designed to be relevant and uninstrusive to a very wide range of USA based customers, especially within the small-medium size sector. If you have clients that are require HIPAA or PCI compliance, this script is still a great place to start.


### Policies and Rules Deployed

This scripts deploys three policies for the different locations covered by DLP. With each policy, there are specific rule sets which will be associated to the parent policy/location.

- Exchange
  - Auto-Detect and automatically Encrypt Sensitive Data going outside of organization.
  - Skip encryption if document is protected or PW protected zip file
  - Provide user with a notification that their email was encrypted, and provide instructions on how to assist the receiving party

- SharePoint + OneDrive
  - BLOCK Sharing Sensitive data using the 'anyone with link' option
  
- Teams + (SharePoint & OneDrive)
  - Detect any volume sensitive data being sent to outside of the organization
  - Require User to provide justification for sharing sensitive info
  - Detect HIGH VOLUMES of sensitive data being shared ourside of org.
  - Provide a report for admin (Not currently functioning)

- Sensitive Information Covered by default
  - U.S. Social Security Number (SSN)
  - Credit Card Number
  - U.S. / U.K. Passport Number
  - U.S. Bank Account Number
  - U.S. Driver's License Number
  - U.S. Individual Taxpayer Identification Number (ITIN)
  - International Banking Account Number (IBAN)
  - Medicare Beneficiary Identifier (MBI) card
  - Other Technical Azure AD Related Information Types

### Prerequisites

- Must have Global Admin
- Must have all powershell modules installed
  Exchange Online Management (Connect-ExchangeOnline)
  Security & Compliance Center (Connect-IPPSSession)
  
