import json

from aws_cdk import aws_cloudtrail as _cloudtrail
from aws_cdk import aws_events as _events
from aws_cdk import aws_events_targets as _targets
from aws_cdk import aws_iam as _iam
from aws_cdk import aws_lambda as _lambda
from aws_cdk import core


class global_args:
    '''
    Helper to define global statics
    '''
    OWNER                       = "MystiqueInfoSecurity"
    ENVIRONMENT                 = "production"
    SOURCE_INFO                 = "https://github.com/miztiik/security-automation-remediate-unintended-iam-access"
    ADMIN_GROUP_NAME            = "admins"


class RemediateUnintendedIamAccessStack(core.Stack):

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # Let us create the DENY ALL policy
        deny_iam_policy_statement = _iam.PolicyStatement(
            resources=['*'],
            actions=['iam:*'],
            effect=_iam.Effect.DENY,
            # sid='DenyIAMPermissions'
        )
        deny_iam_policy_statement.sid="DenyIAMPermissions"

        deny_iam_policy = _iam.ManagedPolicy(
            self,
            "deny_iam_policy",
            description="A policy to deny IAM permissions",
            managed_policy_name="deny_iam_privileges",
            statements = [deny_iam_policy_statement]
        )

        # Lambda Function that will quarantine the user
        try:
            with open("./lambda_src/revoke_iam_privileges.py", mode = 'r') as file:
                revoke_iam_privileges_fn_handler_code = file.read()
        except OSError as e:
            print(f'Unable to read file. ERROR:{str(e)}')

        revoke_iam_privileges_fn = _lambda.Function(
            self,
            id='revokeIamPrivilegesFnId',
            function_name="revoke_iam_privileges_fn",
            runtime=_lambda.Runtime.PYTHON_3_7,
            code=_lambda.InlineCode(revoke_iam_privileges_fn_handler_code),
            handler='index.lambda_handler',
            timeout=core.Duration.seconds(5),
            environment={
                "ADMIN_GROUP_NAME": global_args.ADMIN_GROUP_NAME,
                "DENY_IAM_POLICY_ARN": f"{deny_iam_policy.managed_policy_arn}"
            }
        )

        revoke_iam_privileges_fn_perms=_iam.PolicyStatement(
            effect=_iam.Effect.ALLOW,
            resources=[
                "*",
                ],
            actions=[
                "iam:AttachRolePolicy",
                "iam:AttachUserPolicy",
                "iam:ListAttachedUserPolicies",
                "iam:ListGroupsForUser",
                "iam:PutUserPolicy",
            ]
        )
        revoke_iam_privileges_fn_perms.sid="AllowLambdaToQuarantineUser"
        revoke_iam_privileges_fn.add_to_role_policy( revoke_iam_privileges_fn_perms )


        # Cloudwatch IAM Events Rule
        iam_evant_validator_targets = []
        iam_evant_validator_targets.append(_targets.LambdaFunction(handler=revoke_iam_privileges_fn))
        
        iam_event_pattern = _events.EventPattern(
                source=["aws.iam"],
                detail_type=["AWS API Call via CloudTrail"],
                detail={
                    "eventSource": [
                    "iam.amazonaws.com"
                    ],
                    "userIdentity": {
                    "type": [
                        "IAMUser"
                    ]
                    }
                }
            )

        """
        # Dedicted Event Bus for Security
        sec_event_bus = _events.EventBus(
            self,
            "securityEventBusId",
            event_bus_name=f"{global_args.OWNER}_security_event_bus"
        )
        """

        # Event Rule to trigger Lambda
        iam_event_rule = _events.Rule(self,
            "iamEventRuleId",
            event_pattern = iam_event_pattern,
            rule_name = f"iam_event_pattern_{global_args.OWNER}",
            # event_bus=sec_event_bus,
            enabled = True,
            description = "Trigger an event for IAM Events",
            targets = iam_evant_validator_targets
            )

        # Lets create a cloudtrail to track API events
        _event_trail = _cloudtrail.Trail(
            self,
            "cloudEventTrailId",
            is_multi_region_trail=False,
            include_global_service_events=True,
            enable_file_validation=False,
            send_to_cloud_watch_logs=False
        )

        ###########################################
        ################# OUTPUTS #################
        ###########################################

        output0 = core.CfnOutput(self,
            "SecuirtyAutomationBy",
            value=f"{global_args.SOURCE_INFO}",
            description="To know more about this automation stack, check out our github page."
            )

        output1 = core.CfnOutput(self,
            "LambdaFunction",
            value=(
                f"https://console.aws.amazon.com/lambda/home?region="
                f"{core.Aws.REGION}"
                f"#functions/"
                f"{revoke_iam_privileges_fn.function_name}"
            ),
            description="The Quarantine Lambda Function"
        )

        output2 = core.CfnOutput(self,
            "CreateUser",
            value=(
                f"aws iam create-user --user-name Mystique$RANDOM"
            ),
            description="command to create users"
        )

        output3 = core.CfnOutput(self,
            "DeleteUser",
            value=(
                f"aws iam delete-user --user-name Mystique*"
            ),
            description="command to delete users"
        )
