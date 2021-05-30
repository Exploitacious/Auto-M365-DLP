﻿<#
#################################################
## CONFIGURE OFFICE 365 Data Loss Prevention Policies
#################################################

Connect to Exchange Online via PowerShell using MFA: (Connect-ExchangeOnline)
https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps


Connect to Connect to Security & Compliance Center (Connect-IPPSSession)
https://docs.microsoft.com/en-us/powershell/exchange/connect-to-scc-powershell?view=exchange-ps


## Create New DLP Policy
## https://docs.microsoft.com/en-us/powershell/module/exchange/new-classificationrulecollection?view=exchange-ps

## Create New DLP Rule
## https://docs.microsoft.com/en-us/powershell/module/exchange/new-dlpcompliancerule?view=exchange-ps

Structure of the script:

#  - Policy: Location
#  - - Rule1: Priority 0 
#  - - Rule2: Priority 1

#>


Write-Host
$Answer = Read-Host "Do you want to configure the Data Loss Prevention Policy and rules? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {


$AlertAddress = Read-Host "Enter the Customer's ADMIN EMAIL ADDRESS. This is where you will recieve alerts, notifications and set up admin access to all mailboxes. MUST BE AN INTERNAL ADMIN ADDRESS"


# Connect-ExchangeOnline
# Connect-IPPSSession


Write-Host
Write-Host
# $AlertAddress = Read-Host "Enter the Customer's ADMIN EMAIL ADDRESS where you will recieve alerts about DLP and other notifications. MUST BE AN INTERNAL ADDRESS"
Write-Host
Write-Host


##############
# SENSITIVE INFO Definitions - Sensitive Info High Volume (Count 2+) & Any Volume (1+)
##############


       $SensitiveInfoHigh = @(
            @{Name= "U.S. Social Security Number (SSN)"; minCount="3"; confidencelevel = 'Medium'};
            @{Name= "Credit Card Number"; minCount="3"; confidencelevel = 'Medium'};
         #   @{Name= "Drug Enforcement Agency (DEA) Number"; minCount="3"; confidencelevel = 'Medium'};
         #   @{Name= "U.S. / U.K. Passport Number"}; Known Bug. Needs GUID- See next line
            @{Name= "178ec42a-18b4-47cc-85c7-d62c92fd67f8"; minCount="3"; confidencelevel = 'Medium'};
            @{Name= "U.S. Bank Account Number"; minCount="3"; confidencelevel = 'Medium'};
            @{Name= "U.S. Driver's License Number"; minCount="3"; confidencelevel = 'Medium'};
            @{Name= "U.S. Individual Taxpayer Identification Number (ITIN)"; minCount="3"; confidencelevel = 'Medium'};
            @{Name= "International Banking Account Number (IBAN)"; minCount="3"; confidencelevel = 'Medium'};
            @{Name= "Medicare Beneficiary Identifier (MBI) card"; minCount="3"; confidencelevel = 'Medium'};

            @{Name= "Azure DocumentDB Auth Key"; minCount="3"; confidencelevel = 'Medium'};
            @{Name= "Azure IAAS Database Connection String and Azure SQL Connection String"; minCount="3"; confidencelevel = 'Medium'};
            @{Name= "Azure IoT Connection String"; minCount="3"; confidencelevel = 'Medium'};
            @{Name= "Azure Publish Setting Password"; minCount="3"; confidencelevel = 'Medium'};
            @{Name= "Azure Redis Cache Connection String"; minCount="3"; confidencelevel = 'Medium'};
            @{Name= "Azure SAS"; minCount="3"; confidencelevel = 'Medium'};
            @{Name= "Azure Service Bus Connection String"; minCount="3"; confidencelevel = 'Medium'};
            @{Name= "Azure Storage Account Key"; minCount="3"; confidencelevel = 'Medium'};
            @{Name= "Azure Storage Account Key (Generic)"; minCount="3"; confidencelevel = 'Medium'};

    <#
            @{Name= "Canada Bank Account Number"; minCount="2"};
            @{Name= "Canada Driver's License Number"; minCount="2"};
            @{Name= "Canada Health Service Number"; minCount="2"};
            @{Name= "Canada Passport Number"; minCount="2"};
            @{Name= "Canada Social Insurance Number"; minCount="2"};
            @{Name= "Canada Personal Health Identification Number (PHIN)"; minCount="2"};
            @{Name= "EU Debit Card Number"; minCount="2"};
            @{Name= "EU Driver's License Number"; minCount="2"};
            @{Name= "EU National Identification Number"; minCount="2"};
         #   @{Name= "EU Passport Number"}; Known Bug. Needs GUID- See next line
            @{Name= "21883626-6245-4f3d-9b61-5cbb43e625ee"; minCount="2"};
            @{Name= "EU Social Security Number (SSN) or Equivalent ID"; minCount="2"};
            @{Name= "EU Tax Identification Number (TIN)"; minCount="2"};
            @{Name= "U.K. Driver's License Number"; minCount="2"};
            @{Name= "U.K. Electoral Roll Number"; minCount="2"};
            @{Name= "U.K. National Health Service Number"; minCount="2"};
            @{Name= "U.K. National Insurance Number (NINO)"; minCount="2"};
            @{Name= "U.K. Unique Taxpayer Reference Number"; minCount="2"};
     #>
        )

        $SensitiveInfoLow = @(
            @{Name= "U.S. Social Security Number (SSN)"; minCount="1"; maxCount="2"; confidencelevel = 'Medium'};
            @{Name= "Credit Card Number"; minCount="1"; maxCount="2"; confidencelevel = 'Medium'};
         #   @{Name= "Drug Enforcement Agency (DEA) Number"; minCount="1"; maxCount="2"; confidencelevel = 'Medium'};
         #   @{Name= "U.S. / U.K. Passport Number"}; Known Bug. Needs GUID- See next line
            @{Name= "178ec42a-18b4-47cc-85c7-d62c92fd67f8"; minCount="1"; maxCount="2"; confidencelevel = 'Medium'};
            @{Name= "U.S. Bank Account Number"; minCount="1"; maxCount="2"; confidencelevel = 'Medium'};
            @{Name= "U.S. Driver's License Number"; minCount="1"; maxCount="2"; confidencelevel = 'Medium'};
            @{Name= "U.S. Individual Taxpayer Identification Number (ITIN)"; minCount="1"; maxCount="2"; confidencelevel = 'Medium'};
            @{Name= "International Banking Account Number (IBAN)"; minCount="1"; maxCount="2"; confidencelevel = 'Medium'};
            @{Name= "Medicare Beneficiary Identifier (MBI) card"; minCount="1"; maxCount="2"; confidencelevel = 'Medium'};

            @{Name= "Azure DocumentDB Auth Key"; minCount="1"; maxCount="2"; confidencelevel = 'Medium'};
            @{Name= "Azure IAAS Database Connection String and Azure SQL Connection String"; minCount="1"; maxCount="2"; confidencelevel = 'Medium'};
            @{Name= "Azure IoT Connection String"; minCount="1"; maxCount="2"; confidencelevel = 'Medium'};
            @{Name= "Azure Publish Setting Password"; minCount="1"; maxCount="2"; confidencelevel = 'Medium'};
            @{Name= "Azure Redis Cache Connection String"; minCount="1"; maxCount="2"; confidencelevel = 'Medium'};
            @{Name= "Azure SAS"; minCount="1"; maxCount="2"; confidencelevel = 'Medium'};
            @{Name= "Azure Service Bus Connection String"; minCount="1"; maxCount="2"; confidencelevel = 'Medium'};
            @{Name= "Azure Storage Account Key"; minCount="1"; maxCount="2"; confidencelevel = 'Medium'};
            @{Name= "Azure Storage Account Key (Generic)"; minCount="1"; maxCount="2"; confidencelevel = 'Medium'};
    <#
            @{Name= "Canada Bank Account Number"; minCount="1"};
            @{Name= "Canada Driver's License Number"; minCount="1"};
            @{Name= "Canada Health Service Number"; minCount="1"};
            @{Name= "Canada Passport Number"; minCount="1"};
            @{Name= "Canada Social Insurance Number"; minCount="1"};
            @{Name= "Canada Personal Health Identification Number (PHIN)"; minCount="1"};
            @{Name= "EU Debit Card Number"; minCount="1"};
            @{Name= "EU Driver's License Number"; minCount="1"};
            @{Name= "EU National Identification Number"; minCount="1"};
         #   @{Name= "EU Passport Number"}; Known Bug. Needs GUID- See next line
            @{Name= "21883626-6245-4f3d-9b61-5cbb43e625ee"; minCount="1"};
            @{Name= "EU Social Security Number (SSN) or Equivalent ID"; minCount="1"};
            @{Name= "EU Tax Identification Number (TIN)"; minCount="1"};
            @{Name= "U.K. Driver's License Number"; minCount="1"};
            @{Name= "U.K. Electoral Roll Number"; minCount="1"};
            @{Name= "U.K. National Health Service Number"; minCount="1"};
            @{Name= "U.K. National Insurance Number (NINO)"; minCount="1"};
            @{Name= "U.K. Unique Taxpayer Reference Number"; minCount="1"};
    #>
        )

        $SensitiveInfo = @(
            @{Name= "U.S. Social Security Number (SSN)"; minCount="1"; confidencelevel = 'High'};
            @{Name= "Credit Card Number"; minCount="1"; confidencelevel = 'High'};
         #   @{Name= "Drug Enforcement Agency (DEA) Number"; minCount="1"; confidencelevel = 'High'};
         #   @{Name= "U.S. / U.K. Passport Number"}; Known Bug. Needs GUID- See next line
            @{Name= "178ec42a-18b4-47cc-85c7-d62c92fd67f8"; minCount="1"; confidencelevel = 'High'};
            @{Name= "U.S. Bank Account Number"; minCount="1"; confidencelevel = 'High'};
            @{Name= "U.S. Driver's License Number"; minCount="1"; confidencelevel = 'High'};
            @{Name= "U.S. Individual Taxpayer Identification Number (ITIN)"; minCount="1"; confidencelevel = 'High'};
            @{Name= "International Banking Account Number (IBAN)"; minCount="1"; confidencelevel = 'High'};
            @{Name= "Medicare Beneficiary Identifier (MBI) card"; minCount="1"; confidencelevel = 'High'};

            @{Name= "Azure DocumentDB Auth Key"; minCount="1"; confidencelevel = 'High'};
            @{Name= "Azure IAAS Database Connection String and Azure SQL Connection String"; minCount="1"; confidencelevel = 'High'};
            @{Name= "Azure IoT Connection String"; minCount="1"; confidencelevel = 'High'};
            @{Name= "Azure Publish Setting Password"; minCount="1"; confidencelevel = 'High'};
            @{Name= "Azure Redis Cache Connection String"; minCount="1"; confidencelevel = 'High'};
            @{Name= "Azure SAS"; minCount="1"; confidencelevel = 'High'};
            @{Name= "Azure Service Bus Connection String"; minCount="1"; confidencelevel = 'High'};
            @{Name= "Azure Storage Account Key"; minCount="1"; confidencelevel = 'High'};
            @{Name= "Azure Storage Account Key (Generic)"; minCount="1"; confidencelevel = 'High'};
    <#
            @{Name= "Canada Bank Account Number"; minCount="1"};
            @{Name= "Canada Driver's License Number"; minCount="1"};
            @{Name= "Canada Health Service Number"; minCount="1"};
            @{Name= "Canada Passport Number"; minCount="1"};
            @{Name= "Canada Social Insurance Number"; minCount="1"};
            @{Name= "Canada Personal Health Identification Number (PHIN)"; minCount="1"};
            @{Name= "EU Debit Card Number"; minCount="1"};
            @{Name= "EU Driver's License Number"; minCount="1"};
            @{Name= "EU National Identification Number"; minCount="1"};
         #   @{Name= "EU Passport Number"}; Known Bug. Needs GUID- See next line
            @{Name= "21883626-6245-4f3d-9b61-5cbb43e625ee"; minCount="1"};
            @{Name= "EU Social Security Number (SSN) or Equivalent ID"; minCount="1"};
            @{Name= "EU Tax Identification Number (TIN)"; minCount="1"};
            @{Name= "U.K. Driver's License Number"; minCount="1"};
            @{Name= "U.K. Electoral Roll Number"; minCount="1"};
            @{Name= "U.K. National Health Service Number"; minCount="1"};
            @{Name= "U.K. National Insurance Number (NINO)"; minCount="1"};
            @{Name= "U.K. Unique Taxpayer Reference Number"; minCount="1"};
    #>
        )


#######
# Delete All Other conflicting policies and rules. Only run Once per 60 minutes
#######

 $Answer2 = Read-Host "Do you want to Delete all custom DLP rules and Policices, so that only the new [v1.1] Data Loss Prevention Policies and Rules Apply? This is recommended to do only once, unless you have other custom rules you wish to keep. Type Y or N and press Enter to continue"
                if ($Answer2 -eq 'y' -or $Answer2 -eq 'yes') {

    Get-DlpCompliancePolicy | Remove-DlpCompliancePolicy
    Get-DlpComplianceRule | Remove-DlpComplianceRule

Write-Host
Write-Host
Write-Host -foregroundcolor yellow "All Custom Policies have been deleted."
Write-Host
Write-Host

}




##########
# Exchange Online Policy + Rule - Applies only to Exchange Online
##########

Write-Host
Write-Host -foregroundcolor green "Creating [v1.1] Data Loss Prevention Policy and Rules for Exchange Online."
Write-Host

      $EXoDLPparam = @{
         'Name' = "[Stage 1] Data Loss Prevention EXO [v1.1]";
         'Comment' = "[Stage 1] Data Loss Prevention EXO [v1.1] Imported via PS";
         'Priority' = 0;
         'Mode' = "Enable";
         'ExchangeLocation' = "All"
        }

   New-DlpCompliancePolicy @EXoDLPparam


# All Exchange ; Encrypt-All Automatically and provide policy tip (your message was encrypted...)

      $EXoDLruleParam = @{
         'Name' = "[Stage 1] DLP EXO Rule - Encrypt All [v1.1]";
         'Comment' = "[Stage 1] Data Loss Prevention Exchange Online Rule Encrypt All Outgoing [v1.1] Imported via PS";
         'Disabled' = $False;
         'Priority' = 0;
         'Policy' = "[Stage 1] Data Loss Prevention EXO [v1.1]";
         'ContentContainsSensitiveInformation' = $SensitiveInfo;
         
         'AccessScope' = "NotInOrganization";
      #   'BlockAccessScope' = "PerUser";
         'EncryptRMSTemplate' = "Encrypt"; ## Exchange Only
      #  'DocumentIsPasswordProtected' = $True;
         'ExceptIfDocumentIsPasswordProtected' = $True;

         'NotifyUser' = "LastModifier";
         'NotifyPolicyTipCustomText' = "This email contains sensitive information and will be automatically encrypted when sent.";
         'NotifyEmailCustomText' = "This email contains sensitive information and has been automatically encrypted before being sent. Please see instructions and provide them to the recipient if they are having issues opening the message: https://support.microsoft.com/en-us/topic/how-do-i-open-a-protected-message-1157a286-8ecc-4b1e-ac43-2a608fbf3098";

         'StopPolicyProcessing' = $False;

<#
         'BlockAccess' = $True;
         'RemoveRMSTemplate' = $False;
         'ReportSeverityLevel' = "High";
         'GenerateIncidentReport' = '$Alertaddress';
         'IncidentReportContent' = "Title, DocumentAuthor, DocumentLastModifier, Service, MatchedItem, RulesMatched, Detections, Severity, DetectionDetails, RetentionLabel, SensitivityLabel";
         
         'NotifyAllowOverride' = "FalsePositive","WithJustification";

         'DocumentIsUnsupported' = $False;
         'ExceptIfDocumentIsUnsupported' = $False;
         'HasSenderOverride' = $False;
         'ExceptIfHasSenderOverride' = $False;
         'ProcessingLimitExceeded' = $False;
         'ExceptIfProcessingLimitExceeded' = $False;
#>

    }

    New-DlpComplianceRule @EXoDLruleParam

Write-Host
Write-Host -foregroundcolor green "[v1.1] Data Loss Prevention Policy and Rules for Exchange Online have been created."
Write-Host


##########
# All Locations Policies + Rule(s) - Applies to Teams, SharePoint and OneDrive. Detects and Labels All Sensitive Info.
##########

Write-Host -foregroundcolor green "Creating [v1.1] Data Loss Prevention Policy and Rules for All Non-Exchange Platforms."

      $SPO_ODO_DLP_param = @{
         'Name' = "[Stage 1] Data Loss Prevention for SPO + OD [v1.1]";
         'Comment' = "[Stage 1] Data Loss Prevention for SharePoint and OneDrive [v1.1] Imported via PS";
         'Priority' = 1;
         'Mode' = "Enable";

         'SharePointLocation' = "All";
         # 'SharePointLocationException' = "ToExclude";
         'OneDriveLocation' = "All";
         # 'OneDriveLocationException' = "Exceptions";
         # 'ExceptIfOneDriveSharedBy' = "UsersToExclude";
         # 'ExceptIfOneDriveSharedByMemberOf' = "ExcludeGroups"
        }

   New-DlpCompliancePolicy @SPO_ODO_DLP_param

      $NonEXoDLPparam = @{
         'Name' = "[Stage 1] Data Loss Prevention Non-EXO [v1.1]";
         'Comment' = "[Stage 1] Data Loss Prevention for All Platforms Non-EXO [v1.1] Imported via PS";
         'Priority' = 2;
         'Mode' = "Enable";
         'TeamsLocation' = "All";
         # 'TeamsLocationException' = "ExcludeTeamsGroups";
         'SharePointLocation' = "All";
         # 'SharePointLocationException' = "ToExclude";
         'OneDriveLocation' = "All";
         # 'OneDriveLocationException' = "Exceptions";
         # 'ExceptIfOneDriveSharedBy' = "UsersToExclude";
         # 'ExceptIfOneDriveSharedByMemberOf' = "ExcludeGroups"
        }

   New-DlpCompliancePolicy @NonEXoDLPparam


# SPO + OD ; Any Volume - Block Access to Anonymous Users

      $NonEXoDLruleParamAny = @{
         'Name' = "[Stage 1] DLP Non-EXO Rule - Any Volume [v1.1]";
         'Comment' = "[Stage 1] Data Loss Prevention All Platforms for Non-EXO Rule ANY Volume (Block Anonymous) [v1.1] Imported via PS";
         'Disabled' = $False;
         'Priority' = 0;
         'Policy' = "[Stage 1] Data Loss Prevention for SPO + OD [v1.1]";

        # 'AccessScope' = "NotInOrganization";
         'BlockAccessScope' = "PerAnonymousUser";
         'BlockAccess' = $True;
         'NotifyUser' = "LastModifier";
         'NotifyPolicyTipCustomText' = "File contains sensitive information and can not be shared anonymously";

         'RemoveRMSTemplate' = $False;
         'ContentContainsSensitiveInformation' = $SensitiveInfo;
         'StopPolicyProcessing' = $False;
         'DocumentIsPasswordProtected' = $False;
         'ExceptIfDocumentIsPasswordProtected' = $False;
         'DocumentIsUnsupported' = $False;
         'ExceptIfDocumentIsUnsupported' = $False;
         'HasSenderOverride' = $False;
         'ExceptIfHasSenderOverride' = $False;
         'ProcessingLimitExceeded' = $False;
         'ExceptIfProcessingLimitExceeded' = $False;
         # 'EncryptRMSTemplate' = "Encrypt"; ## Exchange Only
    }

    New-DlpComplianceRule @NonEXoDLruleParamAny


# Non-Exchange ; High-Volume (3 or more occurrences) - Record and Generate Report of High-Volume Sharing

      $NonEXoDLruleParamHigh = @{
         'Name' = "[Stage 1] DLP Non-EXO Rule - High Volume [v1.1]";
         'Comment' = "[Stage 1] Data Loss Prevention All Platforms for Non-EXO Rule High Volume (3+ occurrences) [v1.1] Imported via PS";
         'Disabled' = $False;
         'Priority' = 0;
         'Policy' = "[Stage 1] Data Loss Prevention Non-EXO [v1.1]";

         'AccessScope' = "NotInOrganization";
         'BlockAccessScope' = "PerUser";
         'BlockAccess' = $True;
         'RemoveRMSTemplate' = $False;
         'ReportSeverityLevel' = "High";
         'GenerateIncidentReport' = "SiteAdmin",$AlertAddress;
         'IncidentReportContent' = "Title, DocumentAuthor, DocumentLastModifier, Service, MatchedItem, RulesMatched, Detections, Severity, DetectionDetails, RetentionLabel, SensitivityLabel";
         'NotifyUser' = "LastModifier","SiteAdmin";
         'NotifyAllowOverride' = "FalsePositive","WithJustification";
         'NotifyPolicyTipCustomText' = "File contains more than one instance of sensitive information and can not be shared outside of your organization without a justification. Please see option to override.";

         'ContentContainsSensitiveInformation' = $SensitiveInfoHigh;
         'StopPolicyProcessing' = $False;
         'DocumentIsPasswordProtected' = $False;
         'ExceptIfDocumentIsPasswordProtected' = $False;
         'DocumentIsUnsupported' = $False;
         'ExceptIfDocumentIsUnsupported' = $False;
         'HasSenderOverride' = $False;
         'ExceptIfHasSenderOverride' = $False;
         'ProcessingLimitExceeded' = $False;
         'ExceptIfProcessingLimitExceeded' = $False;
         # 'EncryptRMSTemplate' = "Encrypt"; ## Exchange Only
    }

    New-DlpComplianceRule @NonEXoDLruleParamHigh


# Non-Exchange ; Low-Volume (1-2 occurrences) - Record and Generate Report of High-Volume Sharing

      $NonEXoDLruleParamLow = @{
         'Name' = "[Stage 1] DLP Non-EXO Rule - Low Volume [v1.1]";
         'Comment' = "[Stage 1] Data Loss Prevention All Platforms for Non-EXO Rule Low Volume (1-2 occurrences) [v1.1] Imported via PS";
         'Disabled' = $False;
         'Priority' = 1;
         'Policy' = "[Stage 1] Data Loss Prevention Non-EXO [v1.1]";

         'AccessScope' = "NotInOrganization";
         'BlockAccessScope' = "PerUser";
         'BlockAccess' = $True;
         'RemoveRMSTemplate' = $False;
      #   'ReportSeverityLevel' = "High";
      #   'GenerateIncidentReport' = "SiteAdmin";
      #   'IncidentReportContent' = "Title, DocumentAuthor, DocumentLastModifier, Service, MatchedItem, RulesMatched, Detections, Severity, DetectionDetails, RetentionLabel, SensitivityLabel";
         'NotifyUser' = "LastModifier","SiteAdmin";
         'NotifyAllowOverride' = "FalsePositive","WithJustification";
         'NotifyPolicyTipCustomText' = "File contains more than one instance of sensitive information and can not be shared outside of your organization without a justification. Please see option to override.";

         'ContentContainsSensitiveInformation' = $SensitiveInfoLow;
         'StopPolicyProcessing' = $False;
         'DocumentIsPasswordProtected' = $False;
         'ExceptIfDocumentIsPasswordProtected' = $False;
         'DocumentIsUnsupported' = $False;
         'ExceptIfDocumentIsUnsupported' = $False;
         'HasSenderOverride' = $False;
         'ExceptIfHasSenderOverride' = $False;
         'ProcessingLimitExceeded' = $False;
         'ExceptIfProcessingLimitExceeded' = $False;
         # 'EncryptRMSTemplate' = "Encrypt"; ## Exchange Only
    }

    New-DlpComplianceRule @NonEXoDLruleParamLow



Write-Host
Write-Host -foregroundcolor green "[v1.1] Data Loss Prevention Policy and Rules for All Non-Exchange Platforms have been created."
Write-Host

} ## End Of Script