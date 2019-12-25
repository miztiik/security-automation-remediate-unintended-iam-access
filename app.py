#!/usr/bin/env python3

from aws_cdk import core

from security_automation_remediate_unintended_iam_access.security_automation_remediate_unintended_iam_access_stack import SecurityAutomationRemediateUnintendedIamAccessStack


app = core.App()
SecurityAutomationRemediateUnintendedIamAccessStack(app, "security-automation-remediate-unintended-iam-access")

app.synth()
