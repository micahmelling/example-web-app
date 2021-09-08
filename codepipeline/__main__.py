import pulumi_aws as aws


def main(codecommit_repository_name, codecommit_branch_name, codecommit_repo_arn, ecr_arn, build_role_name,
         build_project_name, network_interface_region, network_interface_owner_id, private_subnet_arn,
         build_s3_bucket_arn, build_vpc_id, private_subnet_id, build_security_group_id, pipeline_role_name,
         pipeline_name, pipeline_s3_bucket_name, pipeline_policy_name, pipeline_s3_bucket_arn, stage_ecs_cluster_name,
         stage_ecs_service_name, prod_ecs_cluster_name, prod_ecs_service_name):
    """
    Creates a CodePipeline to deploy an ECS application. The following structure is employed:
    - GitHub source
    - S3 source
    - CodeBuild build
    - Stage Deploy
    - Manual Approval
    - Prod Deploy

    Appropriate roles and policies are created and used.

    :param pipeline_role_name: name for the execution role to run the pipeline
    :type pipeline_role_name: str
    :param pipeline_name: name of the pipeline
    :type pipeline_name: str
    :param pipeline_s3_bucket_name: name of the s3 bucket
    :type pipeline_s3_bucket_name: str
    :param codecommit_repository_name: name of the git repo
    :type codecommit_repository_name: str
    :param codecommit_branch_name: name of the git branch
    :type codecommit_branch_name: str
    :param codecommit_repo_arn: arn of codecommit repo
    :type codecommit_repo_arn: str
    :param network_interface_region: region of the network interface
    :type network_interface_region: str
    :param network_interface_owner_id: id of the owner of the network interface
    :type network_interface_owner_id: str
    :param private_subnet_arn: private subnet arn for build to run in
    :type private_subnet_arn: str
    :param build_s3_bucket_arn: s3 bucket for build logs
    :type build_s3_bucket_arn: str
    :param build_vpc_id: vpc id for the build
    :type build_vpc_id: str
    :param private_subnet_id: private subnet id for build to run in
    :type private_subnet_id: str
    :param build_security_group_id: security group for the build
    :type build_security_group_id: str
    :param ecr_arn: ARN of ECR image
    :type ecr_arn: str
    :param build_role_name: name for the build role name
    :type build_role_name: str
    :param build_project_name: name of the build project
    :type build_project_name: str
    :param pipeline_policy_name: name for the pipeline policy
    :type pipeline_policy_name: str
    :param pipeline_s3_bucket_arn: arn of the s3 bucket
    :type pipeline_s3_bucket_arn: str
    :param stage_ecs_cluster_name: name of the staging ECS cluster
    :type stage_ecs_cluster_name: str
    :param stage_ecs_service_name: name of the staging ECS service
    :type stage_ecs_service_name: str
    :param prod_ecs_cluster_name: name of the production ECS cluster
    :type prod_ecs_cluster_name: str
    :param prod_ecs_service_name: name of the production ECS service
    :type prod_ecs_service_name: str
    """
    codebuild_role = aws.iam.Role(build_role_name, assume_role_policy="""{
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Principal": {
                "Service": "codebuild.amazonaws.com"
              },
              "Action": "sts:AssumeRole"
            }
          ]
        }
        """)

    role_policy = aws.iam.RolePolicy(f"{build_role_name}_role_policy",
                                     role=codebuild_role.name,
                                     policy=f"""{{
          "Version": "2012-10-17",
          "Statement": [
            {{
              "Effect": "Allow",
              "Resource": [
                "*"
              ],
              "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
              ]
            }},
            {{
              "Effect": "Allow",
              "Action": [
                "ec2:CreateNetworkInterface",
                "ec2:DescribeDhcpOptions",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DeleteNetworkInterface",
                "ec2:DescribeSubnets",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeVpcs"
              ],
              "Resource": "*"
            }},
            {{
              "Effect": "Allow",
              "Action": [
                "ec2:CreateNetworkInterfacePermission"
              ],
              "Resource": [
                "arn:aws:ec2:{network_interface_region}:{network_interface_owner_id}:network-interface/*"
              ],
              "Condition": {{
                "StringEquals": {{
                  "ec2:Subnet": [
                    "{private_subnet_arn}"
                  ],
                  "ec2:AuthorizedService": "codebuild.amazonaws.com"
                }}
              }}
            }},
            {{
              "Effect": "Allow",
              "Action": [
                "*"
              ],
              "Resource": [
                "{build_s3_bucket_arn}",
                "{build_s3_bucket_arn}/*",
                "{pipeline_s3_bucket_arn}",
                "{pipeline_s3_bucket_arn}/*"
              ]
            }},
            {{
              "Effect": "Allow",
              "Action": [
                "ecr:GetRegistryPolicy",
                "ecr:DescribeRegistry",
                "ecr:GetAuthorizationToken",
                "ecr:DeleteRegistryPolicy",
                "ecr:PutRegistryPolicy",
                "ecr:PutReplicationConfiguration"
              ],
              "Resource": [
                "*"
              ]
            }},  
           {{
              "Effect": "Allow",
              "Action": [
                "ecr:*"
              ],
              "Resource": [
                "{ecr_arn}"
              ]
            }}
          ]
        }}
        """)

    codebuild_project = aws.codebuild.Project(build_project_name,
                                              name=build_project_name,
                                              description=f"{build_project_name}_codebuild_project",
                                              build_timeout=15,
                                              queued_timeout=15,
                                              service_role=codebuild_role.arn,
                                              artifacts=aws.codebuild.ProjectArtifactsArgs(
                                                  type="CODEPIPELINE",
                                              ),
                                              environment=aws.codebuild.ProjectEnvironmentArgs(
                                                  compute_type="BUILD_GENERAL1_SMALL",
                                                  image="aws/codebuild/standard:3.0",
                                                  type="LINUX_CONTAINER",
                                                  image_pull_credentials_type="CODEBUILD",
                                                  privileged_mode=True
                                              ),
                                              logs_config=aws.codebuild.ProjectLogsConfigArgs(
                                                  cloudwatch_logs=aws.codebuild.ProjectLogsConfigCloudwatchLogsArgs(
                                                      group_name="log-group",
                                                      stream_name="log-stream",
                                                  ),
                                                  s3_logs=aws.codebuild.ProjectLogsConfigS3LogsArgs(
                                                      status="ENABLED",
                                                      location=build_s3_bucket_arn,
                                                  ),
                                              ),
                                              source=aws.codebuild.ProjectSourceArgs(
                                                  type="CODEPIPELINE",
                                              ),
                                              vpc_config=aws.codebuild.ProjectVpcConfigArgs(
                                                  vpc_id=build_vpc_id,
                                                  subnets=[
                                                      private_subnet_id,
                                                  ],
                                                  security_group_ids=[
                                                      build_security_group_id,
                                                  ],
                                              ),
                                              )

    codepipeline_role = aws.iam.Role(pipeline_role_name, assume_role_policy="""{
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": {
            "Service": "codepipeline.amazonaws.com"
          },
          "Action": "sts:AssumeRole"
        }
      ]
    }
    """)

    codepipeline = aws.codepipeline.Pipeline(pipeline_name,
                                             name=pipeline_name,
                                             role_arn=codepipeline_role.arn,
                                             artifact_store=aws.codepipeline.PipelineArtifactStoreArgs(
                                                 location=pipeline_s3_bucket_name,
                                                 type="S3",
                                             ),
                                             stages=[
                                                 aws.codepipeline.PipelineStageArgs(
                                                     name="Source",
                                                     actions=[
                                                         aws.codepipeline.PipelineStageActionArgs(
                                                             name="CodeSource",
                                                             category="Source",
                                                             owner="AWS",
                                                             provider="CodeCommit",
                                                             version="1",
                                                             output_artifacts=["SourceArtifact"],
                                                             namespace='SourceVariables',
                                                             run_order=1,
                                                             configuration={
                                                                 "RepositoryName": codecommit_repository_name,
                                                                 "BranchName": codecommit_branch_name,
                                                             },
                                                         ),
                                                     ],
                                                 ),
                                                 aws.codepipeline.PipelineStageArgs(
                                                     name="Build",
                                                     actions=[aws.codepipeline.PipelineStageActionArgs(
                                                         name="Build",
                                                         category="Build",
                                                         owner="AWS",
                                                         provider="CodeBuild",
                                                         input_artifacts=["SourceArtifact"],
                                                         output_artifacts=["BuildArtifact"],
                                                         namespace='BuildVariables',
                                                         version="1",
                                                         run_order=1,
                                                         configuration={
                                                             "ProjectName": build_project_name,
                                                         },
                                                     )],
                                                 ),
                                                 aws.codepipeline.PipelineStageArgs(
                                                     name="StageDeploy",
                                                     actions=[aws.codepipeline.PipelineStageActionArgs(
                                                         name="StageDeploy",
                                                         category="Deploy",
                                                         owner="AWS",
                                                         provider="ECS",
                                                         input_artifacts=["BuildArtifact"],
                                                         version="1",
                                                         configuration={
                                                             "ClusterName": stage_ecs_cluster_name,
                                                             "ServiceName": stage_ecs_service_name

                                                         },
                                                     )],
                                                 ),
                                                 aws.codepipeline.PipelineStageArgs(
                                                     name="ManualApproval",
                                                     actions=[aws.codepipeline.PipelineStageActionArgs(
                                                         name="ManualApproval",
                                                         category="Approval",
                                                         owner="AWS",
                                                         provider="Manual",
                                                         version="1",
                                                     )],
                                                 ),
                                                 aws.codepipeline.PipelineStageArgs(
                                                     name="ProdDeploy",
                                                     actions=[aws.codepipeline.PipelineStageActionArgs(
                                                         name="ProdDeploy",
                                                         category="Deploy",
                                                         owner="AWS",
                                                         provider="ECS",
                                                         input_artifacts=["BuildArtifact"],
                                                         version="1",
                                                         configuration={
                                                             "ClusterName": prod_ecs_cluster_name,
                                                             "ServiceName": prod_ecs_service_name,
                                                         },
                                                     )],
                                                 ),
                                             ])

    codepipeline_policy = aws.iam.RolePolicy(pipeline_policy_name,
                                             role=codepipeline_role.id,
                                             policy=f"""{{
      "Version": "2012-10-17",
      "Statement": [
        {{
          "Effect": "Allow",
          "Action": "*",
          "Resource": [
            "{pipeline_s3_bucket_arn}",
            "{pipeline_s3_bucket_arn}/*"
          ]
        }},
        {{
          "Effect": "Allow",
          "Action": "*",
          "Resource": "{codecommit_repo_arn}"
        }},
        {{
          "Effect": "Allow",
          "Action": [
            "codebuild:BatchGetBuilds",
            "codebuild:StartBuild"
          ],
          "Resource": "*"
        }},
        {{
          "Effect": "Allow",
          "Action": [
            "ecs:*"
          ],
          "Resource": "*"
        }},
        {{
            "Action": [
                "iam:PassRole"
            ],
            "Effect": "Allow",
            "Resource": "*",
            "Condition": {{
                "StringLike": {{
                    "iam:PassedToService": [
                        "ecs-tasks.amazonaws.com"
                    ]
                }}
            }}
        }}
      ]
    }}"""
                                             )
