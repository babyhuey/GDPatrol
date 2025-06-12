# GDPatrol

A Serverless Security Orchestration Automation and Response (SOAR) Framework for AWS GuardDuty.
The GDPatrol Lambda function receives the GuardDuty findings through the CloudWatch Event Rule and executes
the appropriate actions to mitigate the threats according to their types and severity.
The deployment script will enable GuardDuty and deploy the GDPatrol Lambda function in all 
supported regions.

## Important Notes

### Network ACL Entry Limits
- Each Network ACL has a limit of 20 rules per direction (inbound/outbound)
- When this limit is reached, GDPatrol will automatically delete the oldest entry to make room for new ones
- The system uses DynamoDB to track entry creation times for proper cleanup

### DynamoDB Tables
The system requires two DynamoDB tables:
1. `GDPatrol` - Stores Network ACL entry information
   - Primary Key: `network_acl_id` (String)
   - Sort Key: `created_at` (String)
2. `GDPatrol_lock` - Used for distributed locking
   - Primary Key: `lock_id` (String)

### Environment Variables
- `DELETE_NACL_ENTRY_DRY_RUN` (default: "False") - Set to "True" to test NACL entry deletion without actually deleting
- `SLACK_WEB_HOOK_URL` - Optional: Webhook URL for Slack notifications

## Supported Actions

* blacklist_ip (at the VPC level, using a Network ACL)
* whitelist_ip
* blacklist_domain (resolves domain to IP and blacklists it)
* quarantine_instance (deny all traffic ingress and egress to the EC2 instance)
* snapshot_instance
* disable_account (disable every action for a particular account)
* disable_ec2_access
* enable_ec2_access
* disable_sg_access (Disable Security Group Access)
* enable_sg_access
* asg_detach_instance (detach instance from an auto scaling group)

The actions to be executed are configured in the config.json file:
```json
{
  "type": "Backdoor:EC2/C&CActivity.B!DNS",
  "actions": ["blacklist_domain", "asg_detach_instance", "quarantine_instance", "snapshot_instance"],
  "reliability": 5
}
```

## Getting Started

### Prerequisites

* Python 3.12 or later
* Boto3 >= 1.34.0
* Requests >= 2.31.0

### Installing
Clone the project and install dependencies:
```bash
python3 -m pip install -r requirements.txt
```

Then run the deployment file:
```bash
python3 deploy.py
```

The deployment script makes the following calls, make sure your account has the appropriate permissions:
```
IAM:
List Roles, Delete Role Policy, Delete Role, Create Role, Put Role Policy

Lambda:
List Functions, Delete Function, Create Function, Add Permission

CloudWatch Events:
List Rules, List Targets By Rule, Remove Targets, Delete Rule, Put Rule, Put Targets

GuardDuty:
List Detectors, Create Detector, Update Detector

Bedrock:
InvokeModel

DynamoDB:
CreateTable, PutItem, DeleteItem, Query, GetItem, UpdateItem
```

## Configuration

You can easily create your own playbooks by just adding or removing the actions and changing the reliability in the config.json
for the desired finding type.

By default, all findings are assigned a reliability value of 5: the reliability is then added to the "severity" value 
found in the finding JSON, and the actions are only executed if the sum of the two values is higher than 10.

This ensures that, by default, only the playbooks for the GuardDuty findings with a severity of 6 or higher will be executed, while 
providing a way to effectively yet simply modify the behavior by modifying the reliability value of the config file.

After any change to the config file locally, run deploy.py again and the script will recreate the Lambda function with 
the updated config.json file.

The GuardDuty findings types are documented [here](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types.html).

## Distributed Locking

GDPatrol uses DynamoDB for distributed locking to prevent race conditions when multiple Lambda functions try to modify Network ACLs simultaneously. The locking mechanism:
- Uses a separate DynamoDB table (`GDPatrol_lock`)
- Implements retry logic with configurable max retries and delay
- Automatically releases locks after operations complete
- Handles lock acquisition failures gracefully

## Authors

* **Antonio Sorrentino** - [https://siemdetection.com](https://siemdetection.com)

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* Most of the actions code was adapted from the AWS Phantom app published by Booz Allen Hamilton.

**Note:** By enabling GuardDuty, you might incur in additional costs. However, since the service is
billed per log consumption usage, the cost should be irrelevant for the regions you're not actively using,
so there's no reason to leave it off as you will want to monitor unused regions as well. See GuardDuty pricing
for more details.