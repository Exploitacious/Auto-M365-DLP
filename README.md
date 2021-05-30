# Auto-M365-DLP
MSP Focused DLP deployment template for M365 Business Premium clients.

The point of this is to deploy an intelligent implementation of DLP on a customer's environment with a simple powershell script, rather than spending hours clicking through the protection.office.com GUI. There are a few things to consider in this script, but it was designed to be relevant and uninstrusive to a very wide range of USA based customers, especially within the small-medium size sector. If you have clients that are require HIPAA or PCI compliance, this script is still a great place to start.

### Prerequisites

- Must have Global Admin
- Must have all powershell modules installed
  Exchange Online Management (Connect-ExchangeOnline)
  Security & Compliance Center (Connect-IPPSSession)
  
