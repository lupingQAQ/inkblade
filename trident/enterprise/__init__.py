# -*- coding: utf-8 -*-
"""企业集成适配层（本地可测，不冒充生产 IdP/SIEM）。

边界：OIDC/LDAP 默认使用 **mock IdP/目录**；Splunk/Elastic/Webhook/Jira/ServiceNow
适配器只保证「请求契约」可被本地 HTTP 收包器验证，真实客户环境仍需联调、
证书/代理/网络白名单与字段映射确认。
"""

from .approval import ApprovalChain, ApprovalError
from .auth import AuthError, LDAPAdapter, MockLDAPDirectory, OIDCAdapter, session_from_identity
from .report_signing import (
    SignoffError,
    create_signoff,
    retention_plan,
    sign_report,
    verify_report,
)
from .siem import (
    DeliveryError,
    ElasticBulk,
    JiraSink,
    ServiceNowSink,
    SplunkHEC,
    WebhookSink,
)

__all__ = [
    "ApprovalChain", "ApprovalError", "AuthError", "LDAPAdapter", "MockLDAPDirectory",
    "OIDCAdapter", "SignoffError", "create_signoff", "retention_plan", "sign_report",
    "verify_report", "DeliveryError", "ElasticBulk", "JiraSink", "ServiceNowSink",
    "SplunkHEC", "WebhookSink", "session_from_identity",
]
