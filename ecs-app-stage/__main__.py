import pulumi_aws as aws
import json

from pulumi import ResourceOptions


def main(cluster_name, vpc_id, alb_security_group_name, ingress_cidr_blocks, app_port, load_balancer_name,
         target_group_name, listener_name, role_arn, task_definition_name, cpu, memory, container_port, container_name,
         docker_image, service_name, task_count, health_check_path, alb_subnet_ids, ecs_security_group_name,
         web_acl_association_name, domain_name, hosted_zone_id, certificate_arn, alb_logs_s3_bucket,
         ecs_subnet_ids, aws_region, ecs_log_group_name, environment, firehose_aws_bucket_arn, firehose_stream_name,
         firehose_stream_arn, account_id, ipset_id, waf_rule_name, waf_acl_name, ecs_role_name, ecs_policies_to_create,
         ecs_policies_to_attach):
    """
    Creates an ECS service that runs a specified number of tasks. An ALB sits ontop of of the ECS service. A Route53
    record is created and forwards traffic to the ALB; this component also enables HTTPS. A WAF protects the ALB.
    Security groups are configured as well to ensure proper security throughout the layers of the application.

    The ECS application runs a Docker container and is exposed over the Internet. The compute is managed by Fargate,
    so we don't have to worry about provisioning and managing servers.

    :param cluster_name: name for the ECS cluster to create
    :type cluster_name: str
    :param vpc_id: VPC id
    :type vpc_id: str
    :param alb_security_group_name: name of the security group to create
    :type alb_security_group_name: str
    :param ingress_cidr_blocks: list of IPs that can access the service
    :type ingress_cidr_blocks: list
    :param app_port: port the app will run on
    :type app_port: int
    :param load_balancer_name: name of the load balancer to create
    :type load_balancer_name: str
    :param target_group_name: name of the target group to create
    :type target_group_name: str
    :param listener_name: name of the listener on the load balancer
    :type listener_name: str
    :param role_arn: arn of the ECS task execution role
    :type role_arn: str
    :param task_definition_name: name of the ECS task definition to create
    :type task_definition_name: str
    :param cpu: CPU units
    :type cpu: str
    :param memory: Memory units
    :type memory: str
    :param container_port: port the container runs on
    :type container_port: int
    :param container_name: name of the Docker container
    :type container_name: str
    :param docker_image: name of or link to the Docker image
    :type docker_image: str
    :param service_name: name of the service to create
    :type service_name: str
    :param task_count: number of tasks to run
    :type task_count: int
    :param health_check_path: path to the health check endpoint
    :type health_check_path: str
    :param alb_subnet_ids: list of subnet IDs in which to put the ECS service
    :type alb_subnet_ids: list
    :param ecs_security_group_name: name of the security group for the ECS service
    :type ecs_security_group_name: str
    :param web_acl_association_name: name to give the Web ACL association
    :type web_acl_association_name: str
    :param domain_name: the name of the domain to associate the application to
    :type domain_name: str
    :param hosted_zone_id: ID of the hosted zone to place the Route53 record in
    :type hosted_zone_id: str
    :param certificate_arn: ARN of the SSL certificate to enable HTTPS on the domain_name
    :type certificate_arn: str
    :param alb_logs_s3_bucket: name of the S3 bucket for ALB logs
    :type alb_logs_s3_bucket: str
    :param ecs_subnet_ids: subnets for the ECS tasks
    :type ecs_subnet_ids: list
    :param aws_region: name of the aws region
    :type aws_region: str
    :param ecs_log_group_name: name of the log group
    :type ecs_log_group_name: str
    :param environment: environment variable to set in ECS task
    :type environment: str
    :param firehose_aws_bucket_arn: ARN of the AWS bucket for the Kinesis Firehose stream
    :type firehose_aws_bucket_arn: str
    :param firehose_stream_name: name of the Kinesis Firehose stream
    :type firehose_stream_name: str
    :param firehose_stream_arn: anticipated ARN of the  Kinesis Firehose stream
    :type firehose_stream_arn: str
    :param account_id: owning account ID
    :type account_id: str
    :param ipset_id: ID of the IP set to use in the WAF
    :type ipset_id: str
    :param waf_rule_name: name of the WAF
    :type waf_rule_name: str
    :param waf_acl_name: name of the WAF ACL
    :type waf_acl_name: str
    :param ecs_role_name: name of the container role to create
    :type ecs_role_name: str
    :param ecs_policies_to_create: policies to create for the ECS role
    :type ecs_policies_to_create: list of tuples, with the first item in the tuple being the policy name and the second
    being the policy string
    :param ecs_policies_to_attach: ARNs of policies to attach
    :type ecs_policies_to_attach: list
    """
    firehose_role = aws.iam.Role(f"firehoseRole_{environment}", assume_role_policy="""{
          "Version": "2012-10-17",
          "Statement": [
            {
              "Action": "sts:AssumeRole",
              "Principal": {
                "Service": "firehose.amazonaws.com"
              },
              "Effect": "Allow",
              "Sid": ""
            }
          ]
        }
        """)

    firehose_role_policy = aws.iam.RolePolicy(f"{firehose_stream_name}_role_policy",
                                              role=firehose_role.name,
                                              policy=f"""{{
        "Version": "2012-10-17",
        "Statement": [
            {{
                "Sid": "",
                "Effect": "Allow",
                "Action": [
                    "glue:GetTable",
                    "glue:GetTableVersion",
                    "glue:GetTableVersions"
                ],
                "Resource": [
                    "arn:aws:glue:us-west-2:{account_id}:catalog",
                    "arn:aws:glue:us-west-2:{account_id}:database/%FIREHOSE_POLICY_TEMPLATE_PLACEHOLDER%",
                    "arn:aws:glue:us-west-2:{account_id}:table/%FIREHOSE_POLICY_TEMPLATE_PLACEHOLDER%/%FIREHOSE_POLICY_TEMPLATE_PLACEHOLDER%"
                ]
            }},
            {{
                "Sid": "",
                "Effect": "Allow",
                "Action": [
                    "s3:AbortMultipartUpload",
                    "s3:GetBucketLocation",
                    "s3:GetObject",
                    "s3:ListBucket",
                    "s3:ListBucketMultipartUploads",
                    "s3:PutObject"
                ],
                "Resource": [
                    "{firehose_aws_bucket_arn}",
                    "{firehose_aws_bucket_arn}/*"
                ]
            }},
            {{
                "Sid": "",
                "Effect": "Allow",
                "Action": [
                    "lambda:InvokeFunction",
                    "lambda:GetFunctionConfiguration"
                ],
                "Resource": "arn:aws:lambda:us-west-2:{account_id}:function:%FIREHOSE_POLICY_TEMPLATE_PLACEHOLDER%"
            }},
            {{
                "Effect": "Allow",
                "Action": [
                    "kms:GenerateDataKey",
                    "kms:Decrypt"
                ],
                "Resource": [
                    "arn:aws:kms:us-west-2:{account_id}:key/%FIREHOSE_POLICY_TEMPLATE_PLACEHOLDER%"
                ],
                "Condition": {{
                    "StringEquals": {{
                        "kms:ViaService": "s3.us-west-2.amazonaws.com"
                    }},
                    "StringLike": {{
                        "kms:EncryptionContext:aws:s3:arn": [
                            "arn:aws:s3:::%FIREHOSE_POLICY_TEMPLATE_PLACEHOLDER%/*"
                        ]
                    }}
                }}
            }},
            {{
                "Sid": "",
                "Effect": "Allow",
                "Action": [
                    "logs:PutLogEvents"
                ],
                "Resource": [
                    "arn:aws:logs:us-west-2:{account_id}:log-group:/aws/kinesisfirehose/{firehose_stream_name}:log-stream:*"
                ]
            }},
            {{
                "Sid": "",
                "Effect": "Allow",
                "Action": [
                    "kinesis:DescribeStream",
                    "kinesis:GetShardIterator",
                    "kinesis:GetRecords",
                    "kinesis:ListShards"
                ],
                "Resource": "arn:aws:kinesis:us-west-2:{account_id}:stream/%FIREHOSE_POLICY_TEMPLATE_PLACEHOLDER%"
            }},
            {{
                "Effect": "Allow",
                "Action": [
                    "kms:Decrypt"
                ],
                "Resource": [
                    "arn:aws:kms:us-west-2:{account_id}:key/%FIREHOSE_POLICY_TEMPLATE_PLACEHOLDER%"
                ],
                "Condition": {{
                    "StringEquals": {{
                        "kms:ViaService": "kinesis.us-west-2.amazonaws.com"
                    }},
                    "StringLike": {{
                        "kms:EncryptionContext:aws:kinesis:arn": "arn:aws:kinesis:us-west-2:{account_id}:stream/%FIREHOSE_POLICY_TEMPLATE_PLACEHOLDER%"
                    }}
                }}
            }}
        ]
        }}"""
                                              )

    firehose_stream = aws.kinesis.FirehoseDeliveryStream(firehose_stream_name,
                                                         destination="s3",
                                                         s3_configuration=
                                                         aws.kinesis.FirehoseDeliveryStreamS3ConfigurationArgs(
                                                             role_arn=firehose_role.arn,
                                                             bucket_arn=firehose_aws_bucket_arn,
                                                             buffer_size=1,
                                                             buffer_interval=60,
                                                         ))

    wafrule = aws.wafregional.Rule(waf_rule_name,
                                   name=waf_rule_name,
                                   metric_name=waf_rule_name,
                                   predicates=[aws.wafregional.RulePredicateArgs(
                                       data_id=ipset_id,
                                       negated=False,
                                       type="IPMatch",
                                   )])

    webacl = aws.wafregional.WebAcl(waf_acl_name,
                                    name=waf_acl_name,
                                    metric_name=waf_acl_name,
                                    default_action=aws.wafregional.WebAclDefaultActionArgs(
                                        type="BLOCK",
                                    ),
                                    rules=[aws.wafregional.WebAclRuleArgs(
                                        action=aws.wafregional.WebAclRuleActionArgs(
                                            type="ALLOW",
                                        ),
                                        priority=1,
                                        rule_id=wafrule.id,
                                        type="REGULAR",
                                    )],
                                    logging_configuration=aws.wafregional.WebAclLoggingConfigurationArgs(
                                        log_destination=aws.get_arn(arn=firehose_stream_arn).arn
                                    ),
                                    opts=ResourceOptions(depends_on=[firehose_stream, wafrule])
                                    )

    ecs_role = aws.iam.Role(
        ecs_role_name,
        name=ecs_role_name,
        assume_role_policy="""{
          "Version": "2012-10-17",
          "Statement": [
            {
              "Action": "sts:AssumeRole",
              "Principal": {
                "Service": "ecs-tasks.amazonaws.com"
              },
              "Effect": "Allow",
              "Sid": ""
            }
          ]
        }
        """
    )

    policy_arns = []
    for policy in ecs_policies_to_create:
        iam_policy = aws.iam.Policy(
            policy[0],
            name=policy[0],
            policy=policy[1]
        )
        policy_arns.append(iam_policy.arn)

    for index, policy_arn in enumerate(policy_arns + ecs_policies_to_attach):
        attach = aws.iam.RolePolicyAttachment(
            f'attached_{index}_{environment}',
            role=ecs_role.name,
            policy_arn=policy_arn
        )

    ecs_cluster = aws.ecs.Cluster(cluster_name, name=cluster_name)

    alb_security_group = aws.ec2.SecurityGroup(alb_security_group_name,
                                               name=alb_security_group_name,
                                               vpc_id=vpc_id,
                                               description='Enable HTTPS access',
                                               ingress=[aws.ec2.SecurityGroupIngressArgs(
                                                   protocol='tcp',
                                                   from_port=app_port,
                                                   to_port=app_port,
                                                   cidr_blocks=ingress_cidr_blocks
                                               )],
                                               egress=[aws.ec2.SecurityGroupEgressArgs(
                                                   protocol='-1',
                                                   from_port=0,
                                                   to_port=0,
                                                   cidr_blocks=['0.0.0.0/0'],
                                               )],
                                               )

    ecs_security_group = aws.ec2.SecurityGroup(ecs_security_group_name,
                                               name=ecs_security_group_name,
                                               vpc_id=vpc_id,
                                               description='Enable ALB Access',
                                               ingress=[
                                                   aws.ec2.SecurityGroupIngressArgs(
                                                       protocol='tcp',
                                                       from_port=container_port,
                                                       to_port=container_port,
                                                       security_groups=[alb_security_group.id]
                                                   )
                                               ],
                                               egress=[aws.ec2.SecurityGroupEgressArgs(
                                                   protocol='-1',
                                                   from_port=0,
                                                   to_port=0,
                                                   cidr_blocks=['0.0.0.0/0'],
                                               )],
                                               )

    load_balancer = aws.lb.LoadBalancer(load_balancer_name,
                                        name=load_balancer_name,
                                        security_groups=[alb_security_group.id],
                                        subnets=alb_subnet_ids,
                                        access_logs=aws.lb.LoadBalancerAccessLogsArgs(
                                            bucket=alb_logs_s3_bucket,
                                            prefix='alb-logs',
                                            enabled=True,
                                        ),
                                        )

    target_group = aws.lb.TargetGroup(target_group_name,
                                      name=target_group_name,
                                      port=container_port,
                                      protocol='HTTPS',
                                      target_type='ip',
                                      vpc_id=vpc_id,
                                      health_check={
                                          "path": f"{health_check_path}",
                                          "port": f"{container_port}",
                                          "protocol": "HTTPS"
                                      }
                                      )

    listener = aws.lb.Listener(listener_name,
                               load_balancer_arn=load_balancer.arn,
                               port=app_port,
                               protocol='HTTPS',
                               certificate_arn=certificate_arn,
                               default_actions=[aws.lb.ListenerDefaultActionArgs(
                                   type='forward',
                                   target_group_arn=target_group.arn,
                               )],
                               )

    web_acl_association = aws.wafregional.WebAclAssociation(web_acl_association_name,
                                                            resource_arn=load_balancer.arn,
                                                            web_acl_id=webacl.id)

    route_53_record = aws.route53.Record(domain_name,
                                         zone_id=hosted_zone_id,
                                         name=domain_name,
                                         type="A",
                                         aliases=[aws.route53.RecordAliasArgs(
                                             name=load_balancer.dns_name,
                                             zone_id=load_balancer.zone_id,
                                             evaluate_target_health=False,
                                         )]
                                         )

    ecs_log_group = aws.cloudwatch.LogGroup(f'ecs/{ecs_log_group_name}', name=f'ecs/{ecs_log_group_name}')

    task_definition = aws.ecs.TaskDefinition(task_definition_name,
                                             family=task_definition_name,
                                             cpu=cpu,
                                             memory=memory,
                                             network_mode='awsvpc',
                                             requires_compatibilities=['FARGATE'],
                                             execution_role_arn=role_arn,
                                             task_role_arn=ecs_role.arn,
                                             container_definitions=json.dumps([{
                                                 'name': container_name,
                                                 'image': docker_image,
                                                 'portMappings': [{
                                                     'containerPort': container_port,
                                                     'protocol': 'tcp'
                                                 }],
                                                 "environment": [
                                                     {
                                                         "name": "ENVIRONMENT",
                                                         "value": f"{environment}"
                                                     }
                                                 ],
                                                 "logConfiguration": {
                                                     "logDriver": "awslogs",
                                                     "options": {
                                                         "awslogs-group": f'ecs/{ecs_log_group_name}',
                                                         "awslogs-region": aws_region,
                                                         "awslogs-stream-prefix": "container-"
                                                     }
                                                 }
                                             }])
                                             )

    ecs_service = aws.ecs.Service(service_name,
                                  cluster=ecs_cluster.arn,
                                  desired_count=task_count,
                                  launch_type='FARGATE',
                                  task_definition=task_definition.arn,
                                  network_configuration=aws.ecs.ServiceNetworkConfigurationArgs(
                                      assign_public_ip=False,
                                      subnets=ecs_subnet_ids,
                                      security_groups=[ecs_security_group.id],
                                  ),
                                  load_balancers=[aws.ecs.ServiceLoadBalancerArgs(
                                      target_group_arn=target_group.arn,
                                      container_name=container_name,
                                      container_port=container_port,
                                  )],
                                  opts=ResourceOptions(depends_on=[listener]),
                                  )
