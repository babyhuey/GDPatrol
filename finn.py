
import boto3
import time
ec2 = boto3.client("ec2")
dynamodb = boto3.client('dynamodb')
nacls = ec2.describe_network_acls()
index = 0
for nacl in nacls["NetworkAcls"]:
  for rule in nacl["Entries"]:
    if rule["Egress"] == False and rule["RuleAction"] == "deny" and rule["RuleNumber"]<32766:

      dynamodb.put_item(
          TableName='GDPatrol',
          Item={
              'network_acl_id': {
                  'S': nacl["NetworkAclId"],
              },
              'created_at': {
                  'S': str(time.time()-index),
              },
              'rule_number': {
                  'S': str(rule["RuleNumber"]),
              }
          },
      )

      print(nacl["NetworkAclId"])
      print(time.time()-index)
      print(rule["RuleNumber"])
      index = index + 2
      time.sleep(1)


# sts = boto3.client("sts")
# r = sts.get_caller_identity()
# print(r['Account'])

# # Create DynamoDB table if not existed
# dynamodb_client = boto3.client('dynamodb')
# try:
#     response = dynamodb_client.create_table(
#         AttributeDefinitions=[
#             {
#                 'AttributeName': 'network_acl_id',
#                 'AttributeType': 'S',
#             },
#             {
#                 'AttributeName': 'created_at',
#                 'AttributeType': 'S',
#             },
#         ],
#         KeySchema=[
#             {
#                 'AttributeName': 'network_acl_id',
#                 'KeyType': 'HASH',
#             },
#             {
#                 'AttributeName': 'created_at',
#                 'KeyType': 'RANGE',
#             },
#         ],
#         ProvisionedThroughput={
#             'ReadCapacityUnits': 5,
#             'WriteCapacityUnits': 5,
#         },
#         TableName='GDPatrol',
#     )
#     print(response)
# except dynamodb_client.exceptions.ResourceInUseException as e:
#     pass


# response = dynamodb_client.query(
#     TableName="GDPatrol",
#     KeyConditionExpression='#pk = :pk_value',
#     ExpressionAttributeNames={'#pk': 'network_acl_id'},
#     ExpressionAttributeValues={':pk_value': {'S': "acl-b35dd8d4"}}
# )

# try:
#     print(response["Items"][0])
#     res = dynamodb_client.delete_item(
#         TableName="GDPatrol",
#         Key={
#             'network_acl_id': response["Items"][0]["network_acl_id"], 
#             'created_at': response["Items"][0]["created_at"]
#         }
#     )
#     print(f"removed {response['Items'][0]}")
# except Exception as e:
#     print(e)
#     pass

# import time
# ts = int(time.time())
# rule_number = int("499")
# for i in range(20):
#     dynamodb_client.put_item(
#         TableName='GDPatrol',
#         Item={
#             'network_acl_id': {
#                 'S': 'acl-b35dd8d4',
#             },
#             'created_at': {
#                 'S': str(ts+i),
#             },
#             'rule_number': {
#                 'S': str(rule_number-i),
#             }
#         },
#     )

# client = boto3.client("ec2")

# client.delete_network_acl_entry(
#     Egress=False,
#     NetworkAclId="acl-b35dd8d4",
#     RuleNumber=499
# )


# client = boto3.client("ec2")
# dynamodb_client = boto3.client('dynamodb')
# nacls = client.describe_network_acls()
# for nacl in nacls["NetworkAcls"]:
#     if (nacl["NetworkAclId"] == "acl-0cf3fb68") :
#         min_rule_id = min(
#             rule["RuleNumber"] for rule in nacl["Entries"] if not rule["Egress"]
#         )
#         print(nacl)


# iam = boto3.client("iam")
# paginator = iam.get_paginator('list_roles')

# for response in paginator.paginate():
#   for role in response['Roles']:
#     if role["RoleName"] == "GDPatrolRole":
#       print(role["RoleName"]) 
